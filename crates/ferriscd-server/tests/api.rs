#![allow(clippy::expect_used, clippy::unwrap_used, clippy::type_complexity)]
//! HTTP-level tests for the control-plane API (`T14.1` + `T14.2`).
//!
//! Every test drives the real router in-process with `tower::ServiceExt::oneshot` and fakes, so
//! nothing here needs a cluster, a Git remote, or a network socket. What the fakes replace is only
//! the *cluster*; the layers under test are the real ones: the router, the auth split, the body
//! limit, the webhook verification/replay/fan-out code, the DTO mapping, the OpenAPI document, and
//! the engine's diff model (including its `Secret` redaction).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use ferriscd_controller::{DiffPreview, SyncPipeline};
use ferriscd_crd::{AppProject, Application};
use ferriscd_engine::diff::{DiffSummary, IgnoreRuleSet, ResourceDiff};
use ferriscd_engine::manifest::ResourceKey;
use ferriscd_server::auth::AuthPolicy;
use ferriscd_server::error::ApiError;
use ferriscd_server::state::{
    AppState, ApplicationSource, ChildNode, ClusterCatalog, ClusterEntry, DiffSource, GraphRequest,
    GraphTraversal, InventoryReader, LiveResourceState, OperationRequest, OperationWriter,
    ProjectCatalog, Readiness, SeamFuture, WorkloadGraphSource,
};
use ferriscd_server::webhooks::{
    self, DeliveryDedupe, RefreshSink, RefreshTarget, WebhookConfig, WebhookSecret,
};
use futures::future::BoxFuture;
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET_VALUE: &str = "super-secret-password-value";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn application(namespace: &str, name: &str) -> Application {
    let spec: ferriscd_crd::ApplicationSpec = serde_json::from_value(json!({
        "project": "default",
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
    app.metadata.resource_version = Some("42".to_owned());
    app.status = Some(ferriscd_crd::status::ApplicationStatus {
        observed_generation: Some(3),
        conditions: vec![ferriscd_crd::status::Condition::new(
            "Ready",
            ferriscd_crd::status::ConditionStatus::True,
            "SyncSucceeded",
            "Reconciled revision 8f3a1c2",
            now(),
        )],
        sync: Some(ferriscd_crd::status::SyncState {
            status: ferriscd_crd::status::SyncStatus::Synced,
            revision: Some("8f3a1c2".to_owned()),
            last_synced_revision: Some("8f3a1c2".to_owned()),
            last_synced_spec_hash: Some("hash".to_owned()),
            revisions: Vec::new(),
            last_synced_at: Some(now()),
        }),
        health: Some(ferriscd_crd::status::HealthState {
            status: ferriscd_crd::status::HealthStatus::Healthy,
            message: Some("All 2 resources are healthy".to_owned()),
        }),
        inventory: vec![
            ferriscd_crd::status::InventoryEntry::new("apps/Deployment/payments/api", "v1"),
            ferriscd_crd::status::InventoryEntry::new("/Service/payments/api", "v1"),
        ],
        operation_state: None,
        history: vec![ferriscd_crd::status::RevisionHistoryEntry::new(
            7,
            Some("8f3a1c2".to_owned()),
            now(),
        )],
        resources: vec![ferriscd_crd::status::ResourceStatus::new(
            "apps/Deployment/payments/api",
            "v1",
            ferriscd_crd::status::HealthStatus::Healthy,
            "3/3 replicas are ready",
        )],
        resources_omitted: 0,
    });
    app
}

/// A fixed timestamp, parsed through `Time`'s own `serde` implementation.
fn now() -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Time {
    serde_json::from_value(serde_json::json!("2027-01-15T10:30:00Z"))
        .expect("a valid RFC 3339 timestamp")
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

struct Projects(Vec<AppProject>);

impl ProjectCatalog for Projects {
    fn list(&self) -> SeamFuture<'_, Vec<AppProject>> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

/// A read-only `ApplicationSet` catalog (`T19.3`).
struct ApplicationSets(Vec<ferriscd_crd::ApplicationSet>);

impl ferriscd_server::state::ApplicationSetCatalog for ApplicationSets {
    fn list(&self) -> SeamFuture<'_, Vec<ferriscd_crd::ApplicationSet>> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

struct Clusters(Vec<ClusterEntry>);

impl ClusterCatalog for Clusters {
    fn list(&self) -> Vec<ClusterEntry> {
        self.0.clone()
    }
}

/// One recorded `ferriscd.io/operation` patch: `(namespace, name, resource version, request)`.
type RecordedPatch = (String, String, Option<String>, OperationRequest);

#[derive(Default)]
struct Operations {
    requests: Mutex<Vec<RecordedPatch>>,
    conflict: bool,
}

impl OperationWriter for Operations {
    fn request<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        resource_version: Option<&'a str>,
        operation: OperationRequest,
    ) -> SeamFuture<'a, ()> {
        Box::pin(async move {
            if self.conflict {
                return Err(ApiError::conflict(
                    "the Application changed under the request",
                ));
            }
            self.requests
                .lock()
                .map_err(|_| ApiError::backend(&"poisoned test state"))?
                .push((
                    namespace.to_owned(),
                    name.to_owned(),
                    resource_version.map(ToOwned::to_owned),
                    operation,
                ));
            Ok(())
        })
    }
}

struct InventoryReaderFake(Vec<LiveResourceState>);

impl InventoryReader for InventoryReaderFake {
    fn read<'a>(&'a self, _app: &'a Application) -> SeamFuture<'a, Vec<LiveResourceState>> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

/// A fake `metadata.ownerReferences` source keyed by `(kind, name)`.
///
/// It also records every traversal it is asked for **and the `GraphTraversal` identity**, so a test
/// can assert that one request shares one traversal (the listing cache/budget scope) and that two
/// requests do not.
#[derive(Default)]
struct Graph {
    children: BTreeMap<(String, String), Vec<ResourceKey>>,
    asked: Mutex<Vec<(String, String, String)>>,
    traversals: Mutex<Vec<u64>>,
}

impl WorkloadGraphSource for Graph {
    fn children(
        &self,
        traversal: &GraphTraversal,
        parent: &GraphRequest<'_>,
    ) -> SeamFuture<'_, Vec<ChildNode>> {
        let key = (parent.kind.to_owned(), parent.name.to_owned());
        self.asked.lock().expect("test state").push((
            parent.namespace.to_owned(),
            parent.kind.to_owned(),
            parent.name.to_owned(),
        ));
        self.traversals
            .lock()
            .expect("test state")
            .push(traversal.id());
        let children = self
            .children
            .get(&key)
            .map(|keys| {
                keys.iter()
                    .map(|key| ChildNode {
                        key: key.clone(),
                        cluster: parent.cluster.to_owned(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Box::pin(async move { Ok(children) })
    }
}

/// A diff source that records which `Application` it was asked about.
#[derive(Default)]
struct Diffs {
    preview: Option<DiffPreview>,
    error: Option<ApiError>,
    asked: Mutex<Vec<(String, String, String)>>,
}

impl DiffSource for Diffs {
    fn diff<'a>(&'a self, app: &'a Application) -> SeamFuture<'a, DiffPreview> {
        self.asked.lock().expect("test state").push((
            app.metadata.namespace.clone().unwrap_or_default(),
            app.metadata.name.clone().unwrap_or_default(),
            app.spec
                .primary_source()
                .map(|source| source.repo_url().to_owned())
                .unwrap_or_default(),
        ));
        let preview = self.preview.clone();
        let error = self.error.clone();
        Box::pin(async move {
            match (preview, error) {
                (_, Some(error)) => Err(error),
                (Some(preview), None) => Ok(preview),
                (None, None) => Ok(preview_of(Vec::new())),
            }
        })
    }
}

struct Ready(bool);

impl Readiness for Ready {
    fn is_ready(&self) -> bool {
        self.0
    }

    fn reason(&self) -> Option<String> {
        (!self.0).then(|| "no Application watch is ready yet".to_owned())
    }
}

/// Records every `ferriscd.io/refresh` request, so a fan-out can be asserted exactly.
#[derive(Default)]
struct Sink {
    refreshed: Mutex<Vec<RefreshTarget>>,
}

impl RefreshSink for Sink {
    fn refresh(&self, target: RefreshTarget) -> SeamFuture<'_, ()> {
        Box::pin(async move {
            self.refreshed
                .lock()
                .map_err(|_| ApiError::backend(&"poisoned test state"))?
                .push(target);
            Ok(())
        })
    }
}

fn preview_of(diffs: Vec<ResourceDiff>) -> DiffPreview {
    DiffPreview {
        revision: "8f3a1c2".to_owned(),
        summary: DiffSummary::from_diffs(&diffs),
        desired: diffs.len(),
        would_sync: !diffs.is_empty(),
        policy_violations: Vec::new(),
        diffs,
    }
}

fn state_with(
    apps: Vec<Application>,
    diffs: Arc<dyn DiffSource>,
    sink: Arc<dyn RefreshSink>,
) -> AppState {
    AppState::new(
        Arc::new(Apps(apps)),
        Arc::new(Projects(Vec::new())),
        Arc::new(Clusters(vec![ClusterEntry {
            name: "in-cluster".to_owned(),
            in_cluster: true,
        }])),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(Vec::new())),
        Arc::new(Graph::default()),
        diffs,
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(sink)
    // These tests exercise the handlers, not authentication: `pass-through` is the documented
    // development escape (`--auth-policy pass-through`), and `T14.3`/`T14.4` have their own suite
    // (`tests/auth_rbac.rs`).
    .with_auth(AuthPolicy::PassThrough)
}

fn state(apps: Vec<Application>) -> AppState {
    state_with(apps, Arc::new(Diffs::default()), Arc::new(Sink::default()))
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

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
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body)
}

/// Lets every ready task run. With a paused clock nothing sleeps for real, so this is a scheduling
/// step, not a wait — the webhook tests are as deterministic as the unit tests.
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// Closes the debounce window of a paused clock and lets the fan-out run.
async fn flush_fan_out() {
    tokio::time::advance(Duration::from_secs(3)).await;
    settle().await;
}

async fn get(state: AppState, path: &str) -> (StatusCode, Value) {
    send(
        state,
        Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .expect("a request"),
    )
    .await
}

async fn post_json(state: AppState, path: &str, body: Value) -> (StatusCode, Value) {
    send(
        state,
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("a request"),
    )
    .await
}

async fn post_raw(
    state: AppState,
    path: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("POST").uri(path);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    send(state, builder.body(Body::from(body)).expect("a request")).await
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_health_probe_answers_ok() {
    let (status, body) = get(state(Vec::new()), "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn the_readiness_probe_reports_the_seam() {
    let (status, body) = get(state(Vec::new()), "/readyz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ready");
    assert!(body.get("reason").is_none());

    let not_ready = state(Vec::new()).with_readiness(Arc::new(Ready(false)));
    let (status, body) = get(not_ready, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "not ready");
    assert_eq!(body["reason"], "no Application watch is ready yet");
}

// ---------------------------------------------------------------------------
// Applications
// ---------------------------------------------------------------------------

#[tokio::test]
async fn applications_are_listed_with_a_redacted_repository_url() {
    let mut app = application("ferriscd-system", "payment-api");
    app.spec
        .source
        .as_mut()
        .expect("spec.source")
        .git
        .as_mut()
        .expect("git source")
        .repo_url =
        "https://oauth2:ghp_averysecrettoken@github.com/example/payment-service.git".to_owned();
    let (status, body) = get(state(vec![app]), "/api/v1/applications").await;
    assert_eq!(status, StatusCode::OK);

    let item = &body["items"][0];
    assert_eq!(item["namespace"], "ferriscd-system");
    assert_eq!(item["name"], "payment-api");
    assert_eq!(item["project"], "default");
    assert_eq!(item["source"]["renderer"], "plainYaml");
    assert_eq!(item["source"]["targetRevision"], "main");
    assert_eq!(item["destination"]["cluster"], "in-cluster");
    // The status strings are the CRD's own wire values, not re-cased by the API: what `kubectl
    // get application` shows is what the API answers.
    assert_eq!(item["sync"]["status"], "Synced");
    assert_eq!(item["health"]["status"], "Healthy");
    assert_eq!(item["resourceCount"], 2);
    assert_eq!(item["observedGeneration"], 3);
    assert_eq!(item["conditions"][0]["type"], "Ready");
    assert_eq!(item["conditions"][0]["status"], "True");
    assert_eq!(item["conditions"][0]["reason"], "SyncSucceeded");

    let rendered = body.to_string();
    assert!(
        !rendered.contains("ghp_averysecrettoken"),
        "a repository URL routinely carries a token and must be redacted: {rendered}"
    );
    assert!(
        rendered.contains("https://oauth2:***@github.com/example/payment-service.git"),
        "the URL stays recognizable while the credential is masked: {rendered}"
    );
}

/// A split OCI chart + aliased Git values `Application` (`T20.1`), with the per-source revisions a
/// finished multi-source pass would have written.
fn multi_source_application(chart_sha: &str, values_sha: &str, composite: &str) -> Application {
    let mut app = application("ferriscd-system", "payment-api");
    app.spec.source = None;
    app.spec.sources = serde_json::from_value(json!([
        {
            "ref": "chart",
            "oci": {"url": "oci://ghcr.io/example/payments", "tag": "1.4.2", "path": ""},
            "renderer": {
                "helm": {
                    "releaseName": "payments",
                    "valueFiles": ["$values/envs/prod/values.yaml"],
                }
            },
        },
        {
            "ref": "values",
            "git": {
                // A remote URL routinely carries a token; the API must never echo it.
                "repoURL": "https://oauth2:ghp_valuesecrettoken@github.com/example/values.git",
                "targetRevision": "main",
            },
        },
    ]))
    .expect("a valid spec.sources list");
    app.spec.validate().expect("the fixture must be valid");

    let status = app.status.as_mut().expect("status");
    let sync = status.sync.as_mut().expect("sync");
    sync.revision = Some(composite.to_owned());
    sync.last_synced_revision = Some(composite.to_owned());
    sync.revisions = vec![chart_sha.to_owned(), values_sha.to_owned()];
    status.history[0].revision = Some(composite.to_owned());
    status.history[0].revisions = vec![chart_sha.to_owned(), values_sha.to_owned()];
    app
}

/// **`T20.1` acceptance criterion.** `multiSource`, every declared source (with its `ref` and
/// whether it renders), and the per-source revisions are surfaced on both the list and the detail
/// payload — and the values repository's credential is redacted on every one of them.
#[tokio::test]
async fn a_multi_source_application_surfaces_sources_and_per_source_revisions() {
    let chart_sha = "1111111111111111111111111111111111111111";
    let values_sha = "2222222222222222222222222222222222222222";
    let composite = format!("sha256:{}", "a".repeat(64));
    let app = multi_source_application(chart_sha, values_sha, &composite);

    let (status, body) = get(state(vec![app.clone()]), "/api/v1/applications").await;
    assert_eq!(status, StatusCode::OK);
    let item = &body["items"][0];

    // The top-level `source` describes the **rendered** entry (the chart), so a client that knows
    // nothing about `spec.sources` still shows the artifact that produced the bundle.
    assert_eq!(item["source"]["multiSource"], json!(true));
    assert_eq!(item["source"]["sourceType"], json!("oci"));
    assert_eq!(item["source"]["targetRevision"], json!("1.4.2"));
    assert_eq!(item["source"]["renderer"], json!("helm"));

    let sources = item["source"]["sources"]
        .as_array()
        .expect("sources must be an array");
    assert_eq!(sources.len(), 2, "declaration order: {sources:?}");
    assert_eq!(sources[0]["ref"], json!("chart"));
    assert_eq!(sources[0]["sourceType"], json!("oci"));
    assert_eq!(
        sources[0]["repoUrl"],
        json!("oci://ghcr.io/example/payments")
    );
    assert_eq!(sources[0]["tag"], json!("1.4.2"));
    assert_eq!(
        sources[0]["renderer"],
        json!("helm"),
        "an entry that renders names its renderer"
    );
    assert_eq!(sources[1]["ref"], json!("values"));
    assert_eq!(sources[1]["sourceType"], json!("git"));
    assert_eq!(sources[1]["targetRevision"], json!("main"));
    assert_eq!(
        sources[1]["repoUrl"],
        json!("https://oauth2:***@github.com/example/values.git"),
        "the values repository URL must be redacted"
    );
    assert!(
        sources[1].get("renderer").is_none(),
        "a values-only source renders nothing, so it has no renderer: {:?}",
        sources[1]
    );

    // Per-source revisions: the whole reason a moved values repository is visible.
    assert_eq!(
        item["sync"]["revisions"],
        json!([chart_sha, values_sha]),
        "status.sync.revisions must be surfaced in declaration order"
    );
    assert_eq!(
        item["sync"]["revision"],
        json!(composite),
        "status.sync.revision stays the composite deployment identity"
    );

    // Nothing the API serves carries the token.
    let rendered = body.to_string();
    assert!(
        !rendered.contains("ghp_valuesecrettoken"),
        "a repository credential must never reach the API: {rendered}"
    );

    // The detail payload carries the same view, plus the history entries a rollback pins.
    let (status, detail) = get(
        state(vec![app]),
        "/api/v1/applications/ferriscd-system/payment-api",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["application"]["source"]["multiSource"], json!(true));
    assert_eq!(
        detail["application"]["source"]["sources"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(
        detail["application"]["sync"]["revisions"],
        json!([chart_sha, values_sha])
    );
    assert_eq!(
        detail["history"][0]["revisions"],
        json!([chart_sha, values_sha]),
        "a history entry records every source revision so a rollback can re-pin them"
    );
    assert_eq!(detail["history"][0]["revision"], json!(composite));
    assert!(
        !detail.to_string().contains("ghp_valuesecrettoken"),
        "the detail payload must redact the credential too"
    );
}

/// Every object key anywhere in `value`, recursively.
fn keys_of(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                into.push(key.clone());
                keys_of(nested, into);
            }
        }
        Value::Array(items) => {
            for item in items {
                keys_of(item, into);
            }
        }
        _ => {}
    }
}

/// **`T20.1` trap guard.** A single-source `Application` must not gain a single byte: `source` and
/// `sync` serialize exactly as the `v1.1` server wrote them, and no `T20.1` key appears anywhere in
/// the payload (including `status.history`).
#[tokio::test]
async fn a_single_source_payload_stays_byte_compatible_with_v1_1() {
    let app = application("ferriscd-system", "payment-api");
    let (status, body) = get(state(vec![app]), "/api/v1/applications").await;
    assert_eq!(status, StatusCode::OK);
    let item = &body["items"][0];

    // The exact `v1.1` bytes of the two DTOs `T20.1` touched.
    assert_eq!(
        serde_json::to_string(&item["source"]).expect("the source view serializes"),
        concat!(
            r#"{"path":"deploy","renderer":"plainYaml","#,
            r#""repoUrl":"https://github.com/example/payment-service.git","#,
            r#""sourceType":"git","targetRevision":"main"}"#
        ),
        "a single-source `source` view must keep its v1.1 wire form"
    );
    assert_eq!(
        serde_json::to_string(&item["sync"]).expect("the sync view serializes"),
        concat!(
            r#"{"lastSyncedAt":"2027-01-15T10:30:00Z","lastSyncedRevision":"8f3a1c2","#,
            r#""revision":"8f3a1c2","status":"Synced"}"#
        ),
        "a single-source `sync` view must keep its v1.1 wire form"
    );

    let mut keys = Vec::new();
    keys_of(&body, &mut keys);
    for added in ["multiSource", "sources", "revisions"] {
        assert!(
            !keys.iter().any(|key| key == added),
            "a single-source payload must not carry the `{added}` key: {body}"
        );
    }

    // The history entry keeps its v1.1 shape too.
    let (status, detail) = get(
        state(vec![application("ferriscd-system", "payment-api")]),
        "/api/v1/applications/ferriscd-system/payment-api",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::to_string(&detail["history"][0]).expect("the history view serializes"),
        r#"{"deployedAt":"2027-01-15T10:30:00Z","id":7,"revision":"8f3a1c2"}"#,
        "a single-source history entry must keep its v1.1 wire form"
    );
    let mut keys = Vec::new();
    keys_of(&detail, &mut keys);
    for added in ["multiSource", "sources", "revisions"] {
        assert!(
            !keys.iter().any(|key| key == added),
            "a single-source detail payload must not carry the `{added}` key: {detail}"
        );
    }
}

#[tokio::test]
async fn one_application_is_readable_with_its_history_and_operation() {
    let mut app = application("ferriscd-system", "payment-api");
    app.status.as_mut().expect("status").operation_state =
        Some(ferriscd_crd::status::OperationState {
            phase: ferriscd_crd::status::OperationPhase::Succeeded,
            sync_phase: None,
            current_wave: 1,
            phase_started_at: None,
            revision: Some("8f3a1c2".to_owned()),
            active_hooks: Vec::new(),
            message: None,
            started_at: now(),
            finished_at: Some(now()),
        });

    let (status, body) = get(
        state(vec![app]),
        "/api/v1/applications/ferriscd-system/payment-api",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["application"]["name"], "payment-api");
    assert_eq!(body["history"][0]["id"], 7);
    assert_eq!(body["history"][0]["revision"], "8f3a1c2");
    assert_eq!(body["operation"]["phase"], "Succeeded");
    assert_eq!(body["operation"]["currentWave"], 1);
}

#[tokio::test]
async fn an_unknown_application_is_a_404_with_a_stable_code() {
    let (status, body) = get(
        state(Vec::new()),
        "/api/v1/applications/ferriscd-system/nope",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "NotFound");
    assert_eq!(
        body["error"]["message"],
        "Application ferriscd-system/nope not found"
    );
}

/// **`T14.1` verification:** the resource graph is inventory + a two-level
/// `ownerReferences` traversal (`Deployment -> ReplicaSet -> Pod`), with per-node live state.
#[tokio::test]
async fn the_resource_graph_stitches_deployment_replicaset_and_pod() {
    let app = application("ferriscd-system", "payment-api");
    let deployment = ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api");
    let replica_set =
        ResourceKey::new("apps", "ReplicaSet", Some("payments".to_owned()), "api-abc");
    let pod = ResourceKey::new("", "Pod", Some("payments".to_owned()), "api-abc-xyz");
    let service = ResourceKey::new("", "Service", Some("payments".to_owned()), "api");

    let mut graph = Graph::default();
    graph.children.insert(
        ("Deployment".to_owned(), "api".to_owned()),
        vec![replica_set.clone()],
    );
    graph.children.insert(
        ("ReplicaSet".to_owned(), "api-abc".to_owned()),
        vec![pod.clone()],
    );
    let graph = Arc::new(graph);

    let mut state = AppState::new(
        Arc::new(Apps(vec![app])),
        Arc::new(Projects(Vec::new())),
        Arc::new(Clusters(Vec::new())),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(vec![
            LiveResourceState {
                key: deployment.clone(),
                present: true,
                ownership: Some("OwnedBySelf"),
            },
            LiveResourceState {
                key: service.clone(),
                present: true,
                ownership: Some("OwnedBySelf"),
            },
        ])),
        graph.clone(),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    );
    state = state
        .with_refresh_sink(Arc::new(Sink::default()))
        .with_auth(AuthPolicy::PassThrough);

    let (status, body) = get(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/resources",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["namespace"], "payments");
    assert_eq!(body["cluster"], "in-cluster");
    assert_eq!(body["syncStatus"], "Synced");
    assert_eq!(body["healthStatus"], "Healthy");
    assert_eq!(body["truncated"], false);

    let nodes = body["nodes"].as_array().expect("nodes");
    assert_eq!(nodes.len(), 4, "{body}");
    assert_eq!(nodes[0]["key"], "apps/Deployment/payments/api");
    assert_eq!(nodes[0]["parent"], Value::Null);
    assert_eq!(nodes[0]["ownership"], "OwnedBySelf");
    assert_eq!(nodes[0]["health"], "Healthy");
    assert_eq!(nodes[0]["healthMessage"], "3/3 replicas are ready");
    let service = nodes
        .iter()
        .find(|node| node["kind"] == "Service")
        .expect("the Service is in the graph");
    assert_eq!(service["key"], "/Service/payments/api");
    assert!(
        service["health"].is_null(),
        "no recorded health, none invented"
    );
    assert!(
        service["parent"].is_null(),
        "a Service has no owner in the graph"
    );
    // The children carry their owner's GKNN, which is what the DAG is built from.
    let replica = nodes
        .iter()
        .find(|node| node["kind"] == "ReplicaSet")
        .expect("the ReplicaSet was stitched in");
    assert_eq!(replica["parent"], "apps/Deployment/payments/api");
    let pod = nodes
        .iter()
        .find(|node| node["kind"] == "Pod")
        .expect("the Pod was stitched in");
    assert_eq!(pod["parent"], "apps/ReplicaSet/payments/api-abc");

    // **Finding `P14-H2` at the handler level:** both levels of one request share **one**
    // `GraphTraversal` (that is the listing cache and the read budget), and a second request gets its
    // own — nothing survives between requests.
    let first_request = graph.traversals.lock().expect("state").clone();
    assert_eq!(
        first_request.len(),
        2,
        "the traversal is asked for the Deployment's and the ReplicaSet's children"
    );
    assert_eq!(
        first_request[0], first_request[1],
        "one request must share one traversal"
    );

    let (status, _) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/resources",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let all = graph.traversals.lock().expect("state").clone();
    assert_eq!(all.len(), 4);
    assert_eq!(
        all[2], all[3],
        "the second request shares its own traversal"
    );
    assert_ne!(
        all[0], all[2],
        "a later request must not reuse the previous request's listing cache"
    );
}

/// A huge inventory cannot produce an unbounded payload.
#[tokio::test]
async fn the_resource_graph_is_capped() {
    let app = application("ferriscd-system", "payment-api");
    let live: Vec<LiveResourceState> = (0..ferriscd_server::api::MAX_GRAPH_NODES + 25)
        .map(|index| LiveResourceState {
            key: ResourceKey::new(
                "",
                "ConfigMap",
                Some("payments".to_owned()),
                format!("config-{index}"),
            ),
            present: true,
            ownership: Some("OwnedBySelf"),
        })
        .collect();
    let state = AppState::new(
        Arc::new(Apps(vec![app])),
        Arc::new(Projects(Vec::new())),
        Arc::new(Clusters(Vec::new())),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(live)),
        Arc::new(Graph::default()),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(Arc::new(Sink::default()))
    .with_auth(AuthPolicy::PassThrough);

    let (status, body) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/resources",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["truncated"], true);
    assert_eq!(
        body["nodes"].as_array().expect("nodes").len(),
        ferriscd_server::api::MAX_GRAPH_NODES
    );
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// **`T14.1` verification + trap guard:** the diff endpoint returns the engine's own
/// `ResourceDiff`s, so a `Secret` never leaves the server — and the preview is computed for the
/// `Application` the cluster actually holds.
#[tokio::test]
async fn the_diff_is_secret_redacted_and_computed_for_the_stored_application() {
    let app = application("ferriscd-system", "payment-api");
    let key = ResourceKey::new("", "Secret", Some("payments".to_owned()), "db");
    let live = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "db", "namespace": "payments"},
        "data": {"password": "b2xkLXBhc3N3b3Jk"},
    });
    let predicted = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "db", "namespace": "payments"},
        "data": {"password": "bmV3LXBhc3N3b3Jk"},
    });
    let diff = ResourceDiff::compare(&key, &live, &predicted, &IgnoreRuleSet::default());
    assert_eq!(diff.status().to_string(), "outOfSync");

    let diffs = Arc::new(Diffs {
        preview: Some(preview_of(vec![diff])),
        ..Diffs::default()
    });
    let state = state_with(vec![app], diffs.clone(), Arc::new(Sink::default()));
    let (status, body) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/diff",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revision"], "8f3a1c2");
    assert_eq!(body["wouldSync"], true);
    assert_eq!(body["summary"]["total"], 1);
    assert_eq!(body["summary"]["outOfSync"], 1);
    assert_eq!(body["resources"][0]["key"], "/Secret/payments/db");
    assert_eq!(body["resources"][0]["status"], "outOfSync");
    let changes = body["resources"][0]["changes"].as_array().expect("changes");
    assert!(!changes.is_empty(), "{body}");
    assert!(
        changes
            .iter()
            .all(|change| change["path"] == "/data/password"),
        "{body}"
    );

    let rendered = body.to_string();
    for raw in [
        "b2xkLXBhc3N3b3Jk",
        "bmV3LXBhc3N3b3Jk",
        "old-password",
        "new-password",
        SECRET_VALUE,
    ] {
        assert!(
            !rendered.contains(raw),
            "the diff must never carry {raw:?}: {rendered}"
        );
    }
    assert!(rendered.contains("***REDACTED(sha256:"), "{rendered}");

    // The preview was computed for the Application the source returned, not for a copy.
    let asked = diffs.asked.lock().expect("state").clone();
    assert_eq!(
        asked,
        vec![(
            "ferriscd-system".to_owned(),
            "payment-api".to_owned(),
            "https://github.com/example/payment-service.git".to_owned()
        )]
    );
}

#[tokio::test]
async fn a_diff_that_cannot_be_computed_is_a_502_and_never_a_fake_synced() {
    let app = application("ferriscd-system", "payment-api");
    let state = state_with(
        vec![app],
        Arc::new(Diffs {
            error: Some(ApiError::backend(&"the destination cluster is unreachable")),
            ..Diffs::default()
        }),
        Arc::new(Sink::default()),
    );
    let (status, body) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/diff",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"]["code"], "BackendUnavailable");
    assert_eq!(
        body["error"]["message"],
        "the destination cluster is unreachable"
    );
}

/// **Shared-engine seam (`T14.1`, finding C9):** the API's diff is the *controller's* pipeline.
///
/// The real `PipelineDiff` adapter is driven here over a fake `SyncPipeline`, proving the endpoint
/// holds no diff state of its own: whatever the pipeline computes is what the API answers, and the
/// pipeline is asked about the same object the API read.
#[tokio::test]
async fn the_diff_endpoint_uses_the_controllers_pipeline() {
    #[derive(Clone)]
    struct FakePipeline {
        asked: Arc<Mutex<Vec<String>>>,
        result: Result<DiffPreview, String>,
    }

    impl SyncPipeline for FakePipeline {
        fn apply<'a>(
            &'a self,
            _app: &'a Application,
        ) -> BoxFuture<
            'a,
            Result<ferriscd_controller::ApplyOutcome, ferriscd_controller::ReconcileError>,
        > {
            Box::pin(async {
                Err(ferriscd_controller::ReconcileError::Invalid {
                    message: "not used".to_owned(),
                })
            })
        }

        fn cleanup<'a>(
            &'a self,
            _app: &'a Application,
            _mode: ferriscd_controller::CleanupMode,
        ) -> BoxFuture<
            'a,
            Result<ferriscd_controller::CleanupOutcome, ferriscd_controller::ReconcileError>,
        > {
            Box::pin(async {
                Err(ferriscd_controller::ReconcileError::Invalid {
                    message: "not used".to_owned(),
                })
            })
        }

        fn diff<'a>(
            &'a self,
            app: &'a Application,
        ) -> BoxFuture<'a, Result<DiffPreview, ferriscd_controller::ReconcileError>> {
            self.asked.lock().expect("state").push(format!(
                "{}/{}",
                app.metadata.namespace.clone().unwrap_or_default(),
                app.metadata.name.clone().unwrap_or_default()
            ));
            let result = self.result.clone();
            Box::pin(async move {
                result.map_err(|message| ferriscd_controller::ReconcileError::Invalid { message })
            })
        }
    }

    let asked = Arc::new(Mutex::new(Vec::new()));
    let pipeline: Arc<dyn SyncPipeline> = Arc::new(FakePipeline {
        asked: asked.clone(),
        result: Ok(DiffPreview {
            revision: "abc123".to_owned(),
            diffs: Vec::new(),
            summary: DiffSummary {
                total: 0,
                synced: 0,
                out_of_sync: 0,
                missing: 0,
                orphaned: 0,
                ownership_conflicts: 0,
                field_conflicts: 0,
            },
            desired: 0,
            would_sync: false,
            policy_violations: Vec::new(),
        }),
    });
    let diffs = Arc::new(ferriscd_server::kube::PipelineDiff::new(pipeline));
    let state = state_with(
        vec![application("ferriscd-system", "payment-api")],
        diffs,
        Arc::new(Sink::default()),
    );
    let (status, body) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/diff",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revision"], "abc123");
    assert_eq!(body["wouldSync"], false);
    assert_eq!(
        *asked.lock().expect("state"),
        vec!["ferriscd-system/payment-api".to_owned()]
    );
}

/// **`T20.2`:** the diff payload carries the policy gate's violations, so `ferriscd app diff` (exit
/// code `3`) and the Web UI's banner can show *why* a sync is refused instead of an opaque error.
#[tokio::test]
async fn the_diff_payload_carries_policy_violations() {
    let app = application("ferriscd-system", "payment-api");
    let mut preview = preview_of(Vec::new());
    preview.would_sync = false;
    preview.policy_violations = vec![
        ferriscd_engine::policy::PolicyViolation {
            rule: "no-privileged".to_owned(),
            enforcement: ferriscd_engine::policy::PolicyEnforcement::Enforce,
            resource_key: "apps/Deployment/payments/api".to_owned(),
            message: "privileged containers are forbidden (policy \"no-privileged\")".to_owned(),
        },
        ferriscd_engine::policy::PolicyViolation {
            rule: "prefer-registry".to_owned(),
            enforcement: ferriscd_engine::policy::PolicyEnforcement::Warn,
            resource_key: "apps/Deployment/payments/api".to_owned(),
            message: "prefer the approved registry (policy \"prefer-registry\")".to_owned(),
        },
    ];
    let diffs = Arc::new(Diffs {
        preview: Some(preview),
        ..Diffs::default()
    });
    let state = state_with(vec![app], diffs, Arc::new(Sink::default()));
    let (status, body) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/diff",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["wouldSync"], false,
        "a blocking violation means the next sync is refused"
    );
    let violations = body["policyViolations"].as_array().expect("violations");
    assert_eq!(violations.len(), 2, "{body}");
    assert_eq!(violations[0]["rule"], "no-privileged");
    assert_eq!(violations[0]["enforcement"], "Enforce");
    assert_eq!(violations[0]["resourceKey"], "apps/Deployment/payments/api");
    assert_eq!(violations[1]["enforcement"], "Warn");
    assert!(
        violations[1]["message"]
            .as_str()
            .is_some_and(|message| message.contains("prefer the approved registry")),
        "{body}"
    );

    // No rule in force (or every rule passing) is an empty array, never an absent field: the Web UI
    // and the CLI both read it directly.
    let state = state_with(
        vec![application("ferriscd-system", "payment-api")],
        Arc::new(Diffs::default()),
        Arc::new(Sink::default()),
    );
    let (status, body) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/diff",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["policyViolations"], json!([]), "{body}");
}

/// A pipeline that cannot preview must not answer "everything is synced": the trait's default
/// implementation refuses, and that refusal reaches the client as an error.
#[tokio::test]
async fn a_pipeline_without_diff_support_refuses_instead_of_inventing_a_result() {
    let pipeline: Arc<dyn SyncPipeline> =
        Arc::new(ferriscd_controller::reconcile::UnwiredSyncPipeline);
    let state = state_with(
        vec![application("ferriscd-system", "payment-api")],
        Arc::new(ferriscd_server::kube::PipelineDiff::new(pipeline)),
        Arc::new(Sink::default()),
    );
    let (status, body) = get(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/diff",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot compute a live diff preview"),
        "{body}"
    );
}

// ---------------------------------------------------------------------------
// Manual operations
// ---------------------------------------------------------------------------

fn operations_state(app: Application, operations: Arc<Operations>) -> AppState {
    AppState::new(
        Arc::new(Apps(vec![app])),
        Arc::new(Projects(Vec::new())),
        Arc::new(Clusters(Vec::new())),
        operations,
        Arc::new(InventoryReaderFake(Vec::new())),
        Arc::new(Graph::default()),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(Arc::new(Sink::default()))
    .with_auth(AuthPolicy::PassThrough)
}

#[tokio::test]
async fn sync_is_accepted_and_records_exactly_the_documented_annotation() {
    let operations = Arc::new(Operations::default());
    let state = operations_state(
        application("ferriscd-system", "payment-api"),
        operations.clone(),
    );

    let (status, body) = post_json(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["operation"], "sync");
    assert_eq!(body["request"], r#"{"sync":{}}"#);
    assert_eq!(body["resourceVersion"], "42");

    let requests = operations.requests.lock().expect("state").clone();
    assert_eq!(requests.len(), 1);
    let (namespace, name, version, operation) = &requests[0];
    assert_eq!(namespace, "ferriscd-system");
    assert_eq!(name, "payment-api");
    assert_eq!(
        version.as_deref(),
        Some("42"),
        "the patch must be conditioned on the resource version the read saw"
    );
    assert_eq!(*operation, OperationRequest::Sync);

    // The annotation value the API records is what the controller parses as a manual sync.
    assert!(matches!(
        ferriscd_engine::sync::parse_rollback_request(&operation.annotation_value()),
        Err(ferriscd_engine::sync::RollbackError::NotARollback)
    ));
}

#[tokio::test]
async fn a_sync_body_asking_for_what_this_release_cannot_do_is_a_422() {
    for body in [
        json!({"prune": true}),
        json!({"dryRun": true}),
        json!({"revision": "deadbeef"}),
    ] {
        let operations = Arc::new(Operations::default());
        let state = operations_state(
            application("ferriscd-system", "payment-api"),
            operations.clone(),
        );
        let (status, response) = post_json(
            state,
            "/api/v1/applications/ferriscd-system/payment-api/sync",
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(response["error"]["code"], "Unprocessable");
        assert!(
            operations.requests.lock().expect("state").is_empty(),
            "a refused request must not patch anything: {body}"
        );
    }
}

/// **Finding `P14-C1`:** a pending *manual sync* is not a conflict. The controller consumes the
/// annotation once a pass settles, so a client that retries (or a UI that double-clicks) must get
/// `202` again — not a `409` that would make the endpoint unusable until somebody deletes an
/// annotation by hand.
#[tokio::test]
async fn a_pending_manual_sync_is_an_idempotent_202() {
    let mut app = application("ferriscd-system", "payment-api");
    app.metadata.annotations = Some(BTreeMap::from([(
        ferriscd_crd::annotations::OPERATION.to_owned(),
        r#"{"sync":{}}"#.to_owned(),
    )]));
    let operations = Arc::new(Operations::default());
    let state = operations_state(app, operations.clone());

    let (status, body) = post_json(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "accepted");
    assert_eq!(body["operation"], "sync");
    assert_eq!(
        body["request"], r#"{"sync":{}}"#,
        "the response reports the request that is already recorded"
    );
    assert!(
        operations.requests.lock().expect("state").is_empty(),
        "an idempotent answer must not re-write the annotation"
    );
}

/// **Finding `P14-C1`:** the annotation is a single slot, so a rollback **supersedes** a pending
/// manual sync instead of being refused. The operator asked for a specific commit most recently.
#[tokio::test]
async fn a_pending_manual_sync_is_superseded_by_a_rollback() {
    let mut app = application("ferriscd-system", "payment-api");
    app.metadata.annotations = Some(BTreeMap::from([(
        ferriscd_crd::annotations::OPERATION.to_owned(),
        r#"{"sync":{}}"#.to_owned(),
    )]));
    let operations = Arc::new(Operations::default());
    let state = operations_state(app, operations.clone());

    let (status, body) = post_json(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        json!({"id": 7}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["operation"], "rollback");
    assert_eq!(body["request"], r#"{"rollback":{"id":7}}"#);
    let requests = operations.requests.lock().expect("state").clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].3, OperationRequest::Rollback { id: 7 });
}

/// A pending **rollback** is the one genuine conflict for a sync: it names a specific commit, and
/// overwriting it would redeploy the wrong one. It is transient (the controller consumes it), so this
/// is not the permanent `409` finding `P14-C1` removed — the rollback itself is accepted while it is
/// there, and a sync is accepted again once it is gone.
#[tokio::test]
async fn a_pending_rollback_blocks_only_a_sync_until_it_is_consumed() {
    let pending = |value: &str| {
        let mut app = application("ferriscd-system", "payment-api");
        app.metadata.annotations = Some(BTreeMap::from([(
            ferriscd_crd::annotations::OPERATION.to_owned(),
            value.to_owned(),
        )]));
        app
    };

    let operations = Arc::new(Operations::default());
    let state = operations_state(pending(r#"{"rollback":{"id":7}}"#), operations.clone());
    let (status, body) = post_json(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "Conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("ferriscd.io/operation"),
        "{body}"
    );
    assert!(operations.requests.lock().expect("state").is_empty());

    // Another rollback is an explicit operator request and replaces the earlier one.
    let (status, body) = post_json(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        json!({"id": 7}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    // Once the controller has consumed the rollback, the same sync succeeds.
    let operations = Arc::new(Operations::default());
    let state = operations_state(
        application("ferriscd-system", "payment-api"),
        operations.clone(),
    );
    let (status, body) = post_json(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(operations.requests.lock().expect("state").len(), 1);
}

#[tokio::test]
async fn a_lost_compare_and_swap_surfaces_as_a_conflict() {
    let operations = Arc::new(Operations {
        conflict: true,
        ..Operations::default()
    });
    let state = operations_state(application("ferriscd-system", "payment-api"), operations);
    let (status, body) = post_json(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "Conflict");
}

#[tokio::test]
async fn rollback_records_the_history_id_and_rejects_an_unknown_one() {
    let operations = Arc::new(Operations::default());
    let state = operations_state(
        application("ferriscd-system", "payment-api"),
        operations.clone(),
    );
    let (status, body) = post_json(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        json!({"id": 7}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["operation"], "rollback");
    assert_eq!(body["request"], r#"{"rollback":{"id":7}}"#);
    let requests = operations.requests.lock().expect("state").clone();
    assert_eq!(requests[0].3, OperationRequest::Rollback { id: 7 });
    assert_eq!(
        ferriscd_engine::sync::parse_rollback_request(&requests[0].3.annotation_value())
            .expect("the controller parses it")
            .id,
        7
    );

    let operations = Arc::new(Operations::default());
    let state = operations_state(
        application("ferriscd-system", "payment-api"),
        operations.clone(),
    );
    let (status, body) = post_json(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        json!({"id": 8}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("known ids: [7]"),
        "{body}"
    );
    assert!(operations.requests.lock().expect("state").is_empty());
}

// ---------------------------------------------------------------------------
// Projects and clusters
// ---------------------------------------------------------------------------

/// **`T19.3`:** the read view exposes each `ApplicationSet`'s generator kinds, its safe
/// deletion/prune defaults, and its generation count — and is empty when no catalog is wired.
#[tokio::test]
async fn applicationsets_are_listed_with_their_generator_and_safety_policy() {
    // The default state has no catalog: a control plane that never opted in still answers 200.
    let (status, body) = get(state(Vec::new()), "/api/v1/applicationsets").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], json!([]));

    let matrix: ferriscd_crd::ApplicationSet = serde_json::from_value(json!({
        "apiVersion": "ferriscd.io/v1alpha1",
        "kind": "ApplicationSet",
        "metadata": {"name": "payments-fleet", "namespace": "ferriscd-system"},
        "spec": {
            "generators": [{"matrix": {"generators": [
                {"clusters": {"selector": {"matchLabels": {"env": "prod"}}}},
                {"git": {"repoURL": "https://github.com/example/config.git", "directories": [{"path": "apps/*"}]}},
            ]}}],
            "template": {
                "metadata": {"name": "{{path.basename}}-{{cluster.name}}"},
                "spec": {
                    "project": "payments",
                    "source": {"git": {"repoURL": "https://github.com/example/payments.git"}},
                    "destination": {"cluster": "{{cluster.name}}", "namespace": "{{path.basename}}"},
                },
            },
            "syncPolicy": {"prune": true},
        },
        "status": {
            "observedGeneration": 4,
            "generatedCount": 6,
            "conditions": [{
                "type": "Ready",
                "status": "True",
                "reason": "ApplicationsGenerated",
                "message": "6 Applications generated",
                "lastTransitionTime": "2027-01-15T10:30:00Z",
            }],
        },
    }))
    .expect("a valid ApplicationSet");

    let state =
        state(Vec::new()).with_applicationset_catalog(Arc::new(ApplicationSets(vec![matrix])));
    let (status, body) = get(state, "/api/v1/applicationsets").await;
    assert_eq!(status, StatusCode::OK);
    let item = &body["items"][0];
    assert_eq!(item["name"], "payments-fleet");
    assert_eq!(item["namespace"], "ferriscd-system");
    assert_eq!(item["generator"], "matrix");
    assert_eq!(item["matrix"], json!(["clusters", "git"]));
    assert_eq!(item["project"], "payments");
    assert_eq!(
        item["preserveResourcesOnDeletion"], true,
        "the non-destructive default is reported, never implied"
    );
    assert_eq!(item["prune"], true);
    assert_eq!(item["generatedCount"], 6);
    assert_eq!(item["observedGeneration"], 4);
    assert_eq!(item["ready"], "True");
}

/// **`T19.3`:** a generated `Application` is badged from its own label; a hand-authored one is not.
#[tokio::test]
async fn applications_carry_the_applicationset_label_in_the_read_view() {
    let mut generated = application("ferriscd-system", "api-prod");
    generated.metadata.labels = Some(BTreeMap::from([(
        ferriscd_crd::APPLICATIONSET_LABEL.to_owned(),
        "payments-fleet".to_owned(),
    )]));
    let hand_authored = application("ferriscd-system", "hand-written");
    let (status, body) = get(
        state(vec![generated, hand_authored]),
        "/api/v1/applications",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["items"].as_array().expect("a list");
    let generated = items
        .iter()
        .find(|item| item["name"] == "api-prod")
        .expect("the generated Application is listed");
    assert_eq!(generated["applicationset"], "payments-fleet");
    let hand_authored = items
        .iter()
        .find(|item| item["name"] == "hand-written")
        .expect("the hand-authored Application is listed");
    assert!(
        hand_authored.get("applicationset").is_none(),
        "an unlabelled Application must not be badged as generated"
    );
}

#[tokio::test]
async fn projects_and_clusters_are_listed() {
    let project: AppProject = serde_json::from_value(json!({
        "apiVersion": "ferriscd.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": "payments", "namespace": "ferriscd-system"},
        "spec": {
            "description": "payments team",
            "sourceRepos": ["https://github.com/example/*"],
            "sourceNamespaces": ["ferriscd-system"],
            "destinations": [{"cluster": "in-cluster", "namespace": "payments"}],
            "allowedServiceAccounts": ["payments:deployer"],
        },
    }))
    .expect("a valid AppProject");

    let state = AppState::new(
        Arc::new(Apps(Vec::new())),
        Arc::new(Projects(vec![project])),
        Arc::new(Clusters(vec![
            ClusterEntry {
                name: "in-cluster".to_owned(),
                in_cluster: true,
            },
            ClusterEntry {
                name: "eu-prod".to_owned(),
                in_cluster: false,
            },
        ])),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(Vec::new())),
        Arc::new(Graph::default()),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(Arc::new(Sink::default()))
    .with_auth(AuthPolicy::PassThrough);

    let (status, body) = get(state.clone(), "/api/v1/projects").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["name"], "payments");
    assert_eq!(body["items"][0]["description"], "payments team");
    assert_eq!(body["items"][0]["destinations"][0], "in-cluster/payments");
    assert_eq!(
        body["items"][0]["allowedServiceAccounts"][0],
        "payments:deployer"
    );

    let (status, body) = get(state, "/api/v1/clusters").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["name"], "in-cluster");
    assert_eq!(body["items"][0]["inCluster"], true);
    assert_eq!(body["items"][1]["name"], "eu-prod");
    assert_eq!(body["items"][1]["inCluster"], false);
}

/// **`T17.4`:** `GET /api/v1/projects` publishes each window **with its live state**, and
/// `GET /api/v1/applications/{ns}/{name}` publishes the verdict the sync dialog has to explain.
///
/// Two windows make the assertions time-independent: `* * * * *` with a one-hour duration is open at
/// every instant, and `0 0 31 2 *` (31 February) never fires, so the project is always "outside its
/// allow window" from the point of view of a manual sync.
#[tokio::test]
async fn sync_windows_are_published_with_their_live_state_and_verdict() {
    let project: AppProject = serde_json::from_value(json!({
        "apiVersion": "ferriscd.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": "payments", "namespace": "ferriscd-system"},
        "spec": {
            "sourceRepos": ["*"],
            "destinations": [{"cluster": "in-cluster", "namespace": "payments"}],
            "syncWindows": [
                {
                    "kind": "deny",
                    "schedule": "0 9-17 * * MON-FRI",
                    "duration": "8h",
                    "timeZone": "America/New_York",
                    "applications": ["payments-*"],
                    "manualSync": true,
                },
                {"kind": "deny", "schedule": "not a schedule", "duration": "2h"},
            ],
        },
    }))
    .expect("a valid AppProject");
    // The application must reference the governed project, or there is no verdict to publish.
    let mut app = application("ferriscd-system", "payment-api");
    app.spec.project = "payments".to_owned();
    let state = AppState::new(
        Arc::new(Apps(vec![app])),
        Arc::new(Projects(vec![project])),
        Arc::new(Clusters(vec![ClusterEntry {
            name: "in-cluster".to_owned(),
            in_cluster: true,
        }])),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(Vec::new())),
        Arc::new(Graph::default()),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(Arc::new(Sink::default()))
    .with_auth(AuthPolicy::PassThrough);

    let (status, body) = get(state.clone(), "/api/v1/projects").await;
    assert_eq!(status, StatusCode::OK);
    let windows = body["items"][0]["syncWindows"]
        .as_array()
        .expect("the windows list");
    assert_eq!(windows.len(), 2, "{body}");
    assert_eq!(windows[0]["kind"], "deny");
    assert_eq!(windows[0]["schedule"], "0 9-17 * * MON-FRI");
    assert_eq!(windows[0]["duration"], "8h");
    assert_eq!(windows[0]["timeZone"], "America/New_York");
    assert_eq!(windows[0]["applications"][0], "payments-*");
    assert_eq!(windows[0]["manualSync"], true);
    assert!(windows[0]["active"].is_boolean());
    // The unparseable entry is reported, not dropped: the project is deny-all while it is broken.
    assert!(
        !windows[1]["error"].as_str().unwrap_or_default().is_empty(),
        "{body}"
    );
    assert!(body["items"][0].get("nextSyncWindowTransition").is_some());

    // The application detail carries the fail-closed verdict for a *manual* sync.
    let (status, body) = get(state, "/api/v1/applications/ferriscd-system/payment-api").await;
    assert_eq!(status, StatusCode::OK);
    let gate = &body["syncWindow"];
    assert_eq!(gate["blocked"], true, "{body}");
    assert_eq!(gate["reason"], "invalidWindow");
    assert_eq!(
        gate["manualOverride"], false,
        "a typo must never open a manual-override backdoor"
    );
    assert!(
        gate["message"]
            .as_str()
            .unwrap_or_default()
            .contains("unusable sync window"),
        "{body}"
    );
}

/// A project without `syncWindows` answers exactly the pre-`T17.4` payload: neither field appears.
#[tokio::test]
async fn a_project_without_sync_windows_keeps_the_previous_payload() {
    let project: AppProject = serde_json::from_value(json!({
        "apiVersion": "ferriscd.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": "payments", "namespace": "ferriscd-system"},
        "spec": {
            "sourceRepos": ["*"],
            "destinations": [{"cluster": "in-cluster", "namespace": "payments"}],
        },
    }))
    .expect("a valid AppProject");
    let state = AppState::new(
        Arc::new(Apps(vec![application("ferriscd-system", "payment-api")])),
        Arc::new(Projects(vec![project])),
        Arc::new(Clusters(Vec::new())),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(Vec::new())),
        Arc::new(Graph::default()),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(Arc::new(Sink::default()))
    .with_auth(AuthPolicy::PassThrough);

    let (_, body) = get(state.clone(), "/api/v1/projects").await;
    assert!(
        body["items"][0].get("syncWindows").is_none(),
        "an empty window list must stay omitted: {body}"
    );
    assert!(body["items"][0].get("nextSyncWindowTransition").is_none());

    let (_, detail) = get(state, "/api/v1/applications/ferriscd-system/payment-api").await;
    assert!(
        detail.get("syncWindow").is_none(),
        "a project with no windows has no verdict to explain: {detail}"
    );
}

/// **Finding M-A:** a caller that can read the `Application` but not the `AppProject` behind it gets
/// **no** `syncWindow` — the field is omitted, never guessed.
///
/// The verdict is derived from a *different object* than the `Application`: `spec.syncWindows` lives
/// on the `AppProject`, and the caller's grant on the `Application` is not a grant on the project
/// (finding M4). So the project has to be resolved *for this request* — visible to the actor and
/// present in the catalogue — and when it is not, the honest answer is silence. Inventing
/// `{"blocked": false}` here would tell a tenant "your change freeze does not exist", which is the
/// one answer that could get a governed project deployed during a freeze.
///
/// The visibility half of that filter rests on the same grant `authorize` has already checked for the
/// `Application`, so the case a request can actually reach is "the project is not one this request may
/// resolve" — exercised here by a catalogue that holds a windowed project for a *different* tenant.
///
/// The test is named for **resolvability**, not visibility (finding M-3): the catalogue lists every
/// `AppProject` and the handler then filters on `actor.can_see(..)`, so what the assertion proves is
/// that an unresolvable project yields no verdict — the RBAC premise above is why a request can never
/// observe a visible-but-unresolvable project, not something this test can trigger.
#[tokio::test]
async fn a_sync_window_verdict_is_omitted_when_the_project_is_not_resolvable() {
    // A windowed project that exists — for someone else. `* * * * *`/`1h` is open at every instant,
    // so if the verdict were derived from it, `syncWindow` would be present and `active`.
    let other_tenant: AppProject = serde_json::from_value(json!({
        "apiVersion": "ferriscd.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": "tenant-b", "namespace": "ferriscd-system"},
        "spec": {
            "sourceRepos": ["*"],
            "destinations": [{"cluster": "in-cluster", "namespace": "tenant-b"}],
            "syncWindows": [
                {"kind": "deny", "schedule": "* * * * *", "duration": "1h"},
            ],
        },
    }))
    .expect("a valid AppProject");
    // The Application itself is readable (pass-through grants every project), and it references
    // `payments`, which this request cannot resolve.
    let mut app = application("ferriscd-system", "payment-api");
    app.spec.project = "payments".to_owned();
    let state = AppState::new(
        Arc::new(Apps(vec![app])),
        Arc::new(Projects(vec![other_tenant])),
        Arc::new(Clusters(Vec::new())),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(Vec::new())),
        Arc::new(Graph::default()),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(Arc::new(Sink::default()))
    .with_auth(AuthPolicy::PassThrough);

    let (status, body) = get(state, "/api/v1/applications/ferriscd-system/payment-api").await;
    assert_eq!(status, StatusCode::OK, "the Application itself is readable");
    assert_eq!(body["application"]["name"], "payment-api", "{body}");
    assert_eq!(body["application"]["project"], "payments", "{body}");
    assert!(
        body.get("syncWindow").is_none(),
        "an unresolvable project must omit the verdict instead of answering `blocked: false`: {body}"
    );
}

/// **Finding M-4:** the application-detail path resolves its **one** project by name.
///
/// The catalogue below answers `get` and **fails** `list` on purpose: a handler that listed the
/// catalogue (to find the project in it) would take the error path and omit the verdict, while one
/// that reads the named object gets it. `syncWindow` being present therefore proves the request
/// issued one scoped `get` instead of a catalogue listing — the cost the finding is about.
struct NamedOnlyProjects(AppProject);

impl ProjectCatalog for NamedOnlyProjects {
    fn list(&self) -> SeamFuture<'_, Vec<AppProject>> {
        Box::pin(async {
            Err(ApiError::backend(
                "the application-detail path must not list the catalogue",
            ))
        })
    }

    fn get(&self, name: &str) -> SeamFuture<'_, Option<AppProject>> {
        let matches = self.0.metadata.name.as_deref() == Some(name);
        Box::pin(async move { Ok(matches.then(|| self.0.clone())) })
    }
}

#[tokio::test]
async fn the_application_detail_resolves_its_project_by_name() {
    // `* * * * *`/`1h` is open at every instant, so the verdict is deterministic.
    let project: AppProject = serde_json::from_value(json!({
        "apiVersion": "ferriscd.io/v1alpha1",
        "kind": "AppProject",
        "metadata": {"name": "payments", "namespace": "ferriscd-system"},
        "spec": {
            "sourceRepos": ["*"],
            "destinations": [{"cluster": "in-cluster", "namespace": "payments"}],
            "syncWindows": [
                {"kind": "deny", "schedule": "* * * * *", "duration": "1h"},
            ],
        },
    }))
    .expect("a valid AppProject");
    let mut app = application("ferriscd-system", "payment-api");
    app.spec.project = "payments".to_owned();
    let state = AppState::new(
        Arc::new(Apps(vec![app])),
        Arc::new(NamedOnlyProjects(project)),
        Arc::new(Clusters(Vec::new())),
        Arc::new(Operations::default()),
        Arc::new(InventoryReaderFake(Vec::new())),
        Arc::new(Graph::default()),
        Arc::new(Diffs::default()),
        Arc::new(Ready(true)),
    )
    .with_refresh_sink(Arc::new(Sink::default()))
    .with_auth(AuthPolicy::PassThrough);

    let (status, body) = get(state, "/api/v1/applications/ferriscd-system/payment-api").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["syncWindow"]["blocked"], true,
        "the named project's open deny window is still reported: {body}"
    );
    assert_eq!(body["syncWindow"]["reason"], "denyWindowActive", "{body}");
}

// ---------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_openapi_document_is_served_and_matches_the_committed_export() {
    let (status, body) = get(state(Vec::new()), "/api/v1/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        ferriscd_server::openapi::document_value().expect("the document is serializable"),
        "the served document is the generated one, in full (never `200 null`)"
    );
    assert!(body["paths"]["/api/v1/applications/{namespace}/{name}/diff"].is_object());

    let generated = ferriscd_server::openapi::document_json_pretty().expect("serializable");
    let committed = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/api/openapi.json"
    ));
    assert_eq!(
        committed.trim_end(),
        generated.trim_end(),
        "docs/api/openapi.json is stale: run `cargo run -p ferriscd-cli -- server openapi`"
    );
}

// ---------------------------------------------------------------------------
// Authentication seam (T14.3)
// ---------------------------------------------------------------------------

/// **`T14.3` seam:** the protected group is default-deny when the policy says so, and the probes and
/// webhooks are *outside* it — so flipping the policy in `T14.3` cannot lock out kubelet probes or a
/// Git server.
#[tokio::test]
async fn the_auth_seam_protects_exactly_the_api_routes() {
    let webhooks = WebhookConfig {
        github_secret: Some(WebhookSecret::new("s3cr3t").expect("secret")),
        max_jitter: Duration::ZERO,
        debounce: Duration::ZERO,
        ..WebhookConfig::default()
    };
    let state = state(vec![application("ferriscd-system", "payment-api")])
        .with_auth(AuthPolicy::DenyAll)
        .with_webhooks(webhooks);

    for path in [
        "/api/v1/applications",
        "/api/v1/applications/ferriscd-system/payment-api",
        "/api/v1/projects",
        // `T19.3`: the read-only `ApplicationSet` view is protected exactly like the rest.
        "/api/v1/applicationsets",
        "/api/v1/clusters",
        "/api/v1/openapi.json",
    ] {
        let (status, body) = get(state.clone(), path).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body["error"]["code"], "Unauthorized");
    }

    // A protected POST is refused before its body is even decoded.
    let (status, _) = post_json(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        json!({"nonsense": true}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Probes stay reachable: kubelet must never need a bearer token.
    assert_eq!(get(state.clone(), "/healthz").await.0, StatusCode::OK);
    assert_eq!(get(state.clone(), "/readyz").await.0, StatusCode::OK);

    // A webhook authenticates with its own secret and is not gated by the bearer policy.
    let body = br#"{"ref":"refs/heads/main","repository":{"html_url":"https://github.com/example/payment-service","default_branch":"main"}}"#.to_vec();
    let signature = github_signature("s3cr3t", &body);
    let (status, _) = post_raw(
        state,
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_SIGNATURE_HEADER, &signature),
            (webhooks::GITHUB_DELIVERY_HEADER, "delivery-1"),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Webhooks
// ---------------------------------------------------------------------------

fn github_signature(secret: &str, body: &[u8]) -> String {
    let digest = webhooks::hmac_sha256(secret.as_bytes(), body);
    let mut signature = String::from("sha256=");
    for byte in digest {
        signature.push_str(&format!("{byte:02x}"));
    }
    signature
}

fn push_body(reference: &str) -> Vec<u8> {
    json!({
        "ref": reference,
        "after": "8f3a1c2",
        "repository": {
            "html_url": "https://github.com/example/payment-service",
            "clone_url": "https://github.com/example/payment-service.git",
            "ssh_url": "git@github.com:example/payment-service.git",
            "default_branch": "main",
        },
    })
    .to_string()
    .into_bytes()
}

fn webhook_state(apps: Vec<Application>, sink: Arc<dyn RefreshSink>) -> AppState {
    state_with(apps, Arc::new(Diffs::default()), sink).with_webhooks(WebhookConfig {
        github_secret: Some(WebhookSecret::new("s3cr3t").expect("secret")),
        gitlab_secret: Some(WebhookSecret::new("glpat-token").expect("secret")),
        debounce: Duration::from_secs(2),
        max_jitter: Duration::ZERO,
        ..WebhookConfig::default()
    })
}

#[tokio::test(start_paused = true)]
async fn a_valid_github_push_is_accepted_and_schedules_one_refresh() {
    let sink = Arc::new(Sink::default());
    let state = webhook_state(
        vec![application("ferriscd-system", "payment-api")],
        sink.clone(),
    );
    let body = push_body("refs/heads/main");
    let signature = github_signature("s3cr3t", &body);
    let (status, response) = post_raw(
        state,
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_SIGNATURE_HEADER, &signature),
            (webhooks::GITHUB_DELIVERY_HEADER, "delivery-1"),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["status"], "accepted");
    assert_eq!(response["matched"], 1);
    assert_eq!(response["reference"], "refs/heads/main");
    assert_eq!(
        response["repository"],
        "https://github.com/example/payment-service"
    );

    // Nothing is refreshed before the debounce window closes, then exactly once.
    assert!(
        sink.refreshed.lock().expect("state").is_empty(),
        "a fan-out must not stampede the API server"
    );
    flush_fan_out().await;
    let refreshed = sink.refreshed.lock().expect("state").clone();
    assert_eq!(
        refreshed,
        vec![RefreshTarget {
            namespace: "ferriscd-system".to_owned(),
            name: "payment-api".to_owned(),
        }]
    );
}

#[tokio::test(start_paused = true)]
async fn a_tampered_github_delivery_is_rejected() {
    let sink = Arc::new(Sink::default());
    let state = webhook_state(
        vec![application("ferriscd-system", "payment-api")],
        sink.clone(),
    );
    let body = push_body("refs/heads/main");
    let signature = github_signature("s3cr3t", &body);
    // Same signature, different body: the HMAC no longer matches.
    let tampered = push_body("refs/heads/main")
        .into_iter()
        .rev()
        .collect::<Vec<u8>>();
    let (status, response) = post_raw(
        state.clone(),
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_SIGNATURE_HEADER, &signature),
            (webhooks::GITHUB_DELIVERY_HEADER, "delivery-tampered"),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        tampered,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(response["error"]["code"], "Unauthorized");

    // No signature at all is refused for the same reason.
    let (status, _) = post_raw(
        state.clone(),
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_DELIVERY_HEADER, "delivery-nosig"),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        push_body("refs/heads/main"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A signature made with a different key is refused, and nothing was scheduled.
    let attacker = github_signature("attacker-key", &push_body("refs/heads/main"));
    let (status, _) = post_raw(
        state,
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_SIGNATURE_HEADER, &attacker),
            (webhooks::GITHUB_DELIVERY_HEADER, "delivery-attacker"),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        push_body("refs/heads/main"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(sink.refreshed.lock().expect("state").is_empty());
}

/// **`T14.2` trap guard:** the 1 MiB cap is enforced *before* any parsing.
#[tokio::test(start_paused = true)]
async fn an_oversized_webhook_body_is_a_413() {
    let sink = Arc::new(Sink::default());
    let state = webhook_state(
        vec![application("ferriscd-system", "payment-api")],
        sink.clone(),
    );
    let mut body = push_body("refs/heads/main");
    body.resize(webhooks::DEFAULT_MAX_BODY_BYTES + 1, b' ');
    let signature = github_signature("s3cr3t", &body);
    let (status, response) = post_raw(
        state.clone(),
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_SIGNATURE_HEADER, &signature),
            (webhooks::GITHUB_DELIVERY_HEADER, "delivery-large"),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{response}");

    // The cap is not webhook-specific: no endpoint accepts an unbounded body.
    let body = vec![b'{'; webhooks::DEFAULT_MAX_BODY_BYTES + 1];
    let (status, response) = post_raw(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        &[("content-type", "application/json")],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{response}");
    assert!(sink.refreshed.lock().expect("state").is_empty());
}

/// **Finding `P14-M1`:** a rejected body carries the crate's `{"error":…}` shape (axum's default
/// rejection body is plain text, which the generated TypeScript client cannot parse), and neither a
/// malformed body nor an oversized one echoes what was sent.
#[tokio::test]
async fn a_rejected_body_uses_the_api_error_shape_and_never_echoes_the_payload() {
    let operations = Arc::new(Operations::default());
    let state = operations_state(
        application("ferriscd-system", "payment-api"),
        operations.clone(),
    );

    // Malformed JSON: `400` with a code and a position, and no part of the payload.
    let payload = br#"{"id": "not-a-number", "secret": "hunter2-value"}"#;
    let (status, response) = post_raw(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        &[("content-type", "application/json")],
        payload.to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "BadRequest");
    let message = response["error"]["message"].as_str().unwrap_or_default();
    assert!(message.contains("line 1"), "{response}");
    for leaked in ["hunter2-value", "not-a-number", "secret"] {
        assert!(
            !response.to_string().contains(leaked),
            "the rejection must not quote the payload: {response}"
        );
    }
    assert!(
        operations.requests.lock().expect("state").is_empty(),
        "a rejected body never reaches the operation writer"
    );

    // A truncated/absent body is the caller's `400` too, not axum's plain-text rejection.
    let (status, response) = post_raw(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
    assert_eq!(response["error"]["code"], "BadRequest");

    // An oversized body is the documented `413`, in the same shape.
    let (status, response) = post_raw(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/rollback",
        &[("content-type", "application/json")],
        vec![b' '; webhooks::DEFAULT_MAX_BODY_BYTES + 1],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{response}");
    assert_eq!(response["error"]["code"], "PayloadTooLarge");
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(&webhooks::DEFAULT_MAX_BODY_BYTES.to_string()),
        "the error names the limit that was exceeded: {response}"
    );

    // ... on `/sync` too, whose body is optional.
    let (status, response) = post_raw(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        &[("content-type", "application/json")],
        vec![b' '; webhooks::DEFAULT_MAX_BODY_BYTES + 1],
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{response}");
    assert_eq!(response["error"]["code"], "PayloadTooLarge");

    // An empty body is *not* an error on `/sync` (nothing in the request body is required).
    let (status, response) = post_raw(
        state,
        "/api/v1/applications/ferriscd-system/payment-api/sync",
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{response}");
    assert_eq!(operations.requests.lock().expect("state").len(), 1);
}

/// **`T14.2` verification:** a replayed `X-GitHub-Delivery` is ignored, and it does not schedule a
/// second fan-out.
#[tokio::test(start_paused = true)]
async fn a_duplicate_delivery_is_ignored() {
    let sink = Arc::new(Sink::default());
    let state = webhook_state(
        vec![application("ferriscd-system", "payment-api")],
        sink.clone(),
    );
    let body = push_body("refs/heads/main");
    let signature = github_signature("s3cr3t", &body);
    let headers = [
        (webhooks::GITHUB_SIGNATURE_HEADER, signature.as_str()),
        (webhooks::GITHUB_DELIVERY_HEADER, "delivery-replayed"),
        (webhooks::GITHUB_EVENT_HEADER, "push"),
    ];
    let (status, first) = post_raw(
        state.clone(),
        "/api/v1/webhooks/github",
        &headers,
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["status"], "accepted");

    let (status, second) = post_raw(state, "/api/v1/webhooks/github", &headers, body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a replay is not an error (GitHub would retry it)"
    );
    assert_eq!(second["status"], "duplicate");
    assert_eq!(second["matched"], Value::Null);
    assert!(
        second["message"]
            .as_str()
            .unwrap_or_default()
            .contains("delivery-replayed"),
        "{second}"
    );

    flush_fan_out().await;
    assert_eq!(
        sink.refreshed.lock().expect("state").len(),
        1,
        "the replay must not produce a second fan-out"
    );
}

#[tokio::test(start_paused = true)]
async fn a_missing_delivery_id_is_a_400_and_a_missing_secret_refuses_service() {
    let sink = Arc::new(Sink::default());
    let state = webhook_state(Vec::new(), sink);
    let body = push_body("refs/heads/main");
    let signature = github_signature("s3cr3t", &body);
    let (status, response) = post_raw(
        state,
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_SIGNATURE_HEADER, &signature),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(response["error"]["code"], "BadRequest");

    // No configured secret: the endpoint refuses rather than accepting unverified deliveries.
    let unconfigured = state_with(
        Vec::new(),
        Arc::new(Diffs::default()),
        Arc::new(Sink::default()),
    );
    let (status, response) = post_raw(
        unconfigured,
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_DELIVERY_HEADER, "d"),
            (webhooks::GITHUB_EVENT_HEADER, "push"),
        ],
        push_body("refs/heads/main"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not configured"),
        "{response}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_non_push_github_event_is_ignored_without_scheduling_anything() {
    let sink = Arc::new(Sink::default());
    let state = webhook_state(
        vec![application("ferriscd-system", "payment-api")],
        sink.clone(),
    );
    let body = push_body("refs/heads/main");
    let signature = github_signature("s3cr3t", &body);
    let (status, response) = post_raw(
        state,
        "/api/v1/webhooks/github",
        &[
            (webhooks::GITHUB_SIGNATURE_HEADER, &signature),
            (webhooks::GITHUB_DELIVERY_HEADER, "delivery-issues"),
            (webhooks::GITHUB_EVENT_HEADER, "issues"),
        ],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["status"], "ignored");
    assert!(
        response["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not a push"),
        "{response}"
    );
    flush_fan_out().await;
    assert!(sink.refreshed.lock().expect("state").is_empty());
}

/// **`T14.2` verification:** one push matching several `Application`s produces one coalesced
/// fan-out, and every matched application is refreshed exactly once.
#[tokio::test(start_paused = true)]
async fn a_monorepo_push_fans_out_once_per_application() {
    let sink = Arc::new(Sink::default());
    let mut apps = Vec::new();
    for name in ["api", "worker", "cron"] {
        let mut app = application("ferriscd-system", name);
        app.spec
            .source
            .as_mut()
            .expect("spec.source")
            .git
            .as_mut()
            .expect("git source")
            .repo_url = "git@github.com:example/payment-service.git".to_owned();
        apps.push(app);
    }
    // An application tracking a different branch must not be woken.
    let mut other = application("ferriscd-system", "release-only");
    other
        .spec
        .source
        .as_mut()
        .expect("spec.source")
        .git
        .as_mut()
        .expect("git source")
        .target_revision = "release/1.2".to_owned();
    apps.push(other);

    let state = webhook_state(apps, sink.clone());
    let body = push_body("refs/heads/main");
    let signature = github_signature("s3cr3t", &body);
    for delivery in ["d-1", "d-2", "d-3"] {
        let (status, response) = post_raw(
            state.clone(),
            "/api/v1/webhooks/github",
            &[
                (webhooks::GITHUB_SIGNATURE_HEADER, &signature),
                (webhooks::GITHUB_DELIVERY_HEADER, delivery),
                (webhooks::GITHUB_EVENT_HEADER, "push"),
            ],
            body.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["matched"], 3, "{response}");
    }

    flush_fan_out().await;
    let mut refreshed = sink.refreshed.lock().expect("state").clone();
    refreshed.sort();
    assert_eq!(
        refreshed,
        vec![
            RefreshTarget {
                namespace: "ferriscd-system".to_owned(),
                name: "api".to_owned(),
            },
            RefreshTarget {
                namespace: "ferriscd-system".to_owned(),
                name: "cron".to_owned(),
            },
            RefreshTarget {
                namespace: "ferriscd-system".to_owned(),
                name: "worker".to_owned(),
            },
        ],
        "three deliveries inside the window must produce one fan-out of three"
    );
}

#[tokio::test(start_paused = true)]
async fn a_valid_gitlab_push_is_accepted_and_a_wrong_token_is_rejected() {
    let sink = Arc::new(Sink::default());
    let state = webhook_state(
        vec![application("ferriscd-system", "payment-api")],
        sink.clone(),
    );
    let body = json!({
        "object_kind": "push",
        "ref": "refs/heads/main",
        "project": {
            "web_url": "https://github.com/example/payment-service",
            "git_ssh_url": "git@github.com:example/payment-service.git",
            "default_branch": "main",
        },
    })
    .to_string()
    .into_bytes();

    let (status, response) = post_raw(
        state.clone(),
        "/api/v1/webhooks/gitlab",
        &[
            (webhooks::GITLAB_TOKEN_HEADER, "glpat-token"),
            (webhooks::GITLAB_EVENT_HEADER, "Push Hook"),
        ],
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["status"], "accepted");
    assert_eq!(response["matched"], 1);

    let (status, _) = post_raw(
        state.clone(),
        "/api/v1/webhooks/gitlab",
        &[
            (webhooks::GITLAB_TOKEN_HEADER, "glpat-wrong"),
            (webhooks::GITLAB_EVENT_HEADER, "Push Hook"),
        ],
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // GitLab has no HMAC: a missing token is a refusal, never an unauthenticated pass.
    let (status, _) = post_raw(
        state,
        "/api/v1/webhooks/gitlab",
        &[(webhooks::GITLAB_EVENT_HEADER, "Push Hook")],
        body,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The replay cache is bounded: a flood of distinct ids cannot grow memory without limit.
#[test]
fn the_replay_cache_is_bounded() {
    let dedupe = DeliveryDedupe::new(8, Duration::from_secs(60));
    for index in 0..1_000 {
        assert!(dedupe.admit(&format!("delivery-{index}")));
    }
    assert_eq!(dedupe.len(), 8);
}
