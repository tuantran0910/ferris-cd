#![allow(clippy::expect_used, clippy::unwrap_used)]
//! HTTP-level tests for API authentication (`T14.3`) and project-scoped authorization (`T14.4`).
//!
//! Everything runs in-process with `tower::ServiceExt::oneshot`: the *real* router, the *real*
//! middleware chain, the *real* RBAC matcher and the *real* diff/list DTOs, with only the cluster
//! and the `TokenReview` call replaced by fakes. The two fakes are deliberately the only seams:
//!
//! * [`Tokens`] is a table of `token -> identity` with a call counter, so the positive cache, the
//!   `401` paths and the "one review per identity per 30 s" claim are all asserted, not assumed.
//! * the policy is a real [`RbacPolicy`] parsed from the documented YAML, exactly as the binary
//!   parses `ferriscd-rbac-cm`.
//!
//! The live `TokenReview` round trip against a real API server is
//! `tests/integration/v1_0_control_plane_auth.rs` (`#[ignore]`, `kind` only).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode, header};
use ferriscd_controller::DiffPreview;
use ferriscd_crd::{AppProject, Application};
use ferriscd_engine::diff::{DiffSummary, IgnoreRuleSet, ResourceDiff};
use ferriscd_engine::manifest::ResourceKey;
use ferriscd_server::auth::{AuthPolicy, AuthenticatedIdentity, IdentityCache, TokenAuthenticator};
use ferriscd_server::error::ApiError;
use ferriscd_server::rbac::RbacPolicy;
use ferriscd_server::state::{
    AppState, ApplicationSource, ChildNode, ClusterCatalog, ClusterEntry, DiffSource, GraphRequest,
    GraphTraversal, InventoryReader, LiveResourceState, OperationRequest, OperationWriter,
    ProjectCatalog, Readiness, SeamFuture, WorkloadGraphSource,
};
use ferriscd_server::webhooks::{self, RefreshSink, RefreshTarget, WebhookConfig, WebhookSecret};
use serde_json::{Value, json};
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The identity a valid token resolves to, as Kubernetes would report it for a `ServiceAccount`.
const TEAM_USER: &str = "system:serviceaccount:ferriscd-system:payments-deployer";
const TEAM_GROUP: &str = "payments-team";
const ADMIN_USER: &str = "system:serviceaccount:ferriscd-system:platform-admin";
const ADMIN_GROUP: &str = "platform-admins";
const TENANT_A_USER: &str = "system:serviceaccount:ferriscd-system:tenant-a";
const TENANT_A_GROUP: &str = "tenant-a";

/// The policy an operator publishes in `ferriscd-rbac-cm`.
///
/// `payments-team` is a **read-only** tenant (get + diff); `tenant-a` owns a different project;
/// `platform-admins` is the wildcard admin used by the "admin" test.
const POLICY: &str = r#"
rules:
  - subject: {kind: group, name: platform-admins}
    project: "*"
    actions: [admin]
  - subject: {kind: group, name: payments-team}
    project: payments
    actions: [get, diff]
  - subject: {kind: group, name: tenant-a}
    project: tenant-a
    actions: [get, diff, sync]
"#;

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
    app.metadata.resource_version = Some("42".to_owned());
    app.status = Some(ferriscd_crd::status::ApplicationStatus {
        history: vec![ferriscd_crd::status::RevisionHistoryEntry::new(
            7,
            Some("8f3a1c2".to_owned()),
            timestamp(),
        )],
        ..ferriscd_crd::status::ApplicationStatus::default()
    });
    app
}

fn timestamp() -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Time {
    serde_json::from_value(serde_json::json!("2027-01-15T10:30:00Z"))
        .expect("a valid RFC 3339 timestamp")
}

/// The cluster, replaced by a table: the only fake state the handlers read.
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

struct Clusters(Vec<ClusterEntry>);

impl ClusterCatalog for Clusters {
    fn list(&self) -> Vec<ClusterEntry> {
        self.0.clone()
    }
}

/// Records every `ferriscd.io/operation` write, so a `403` can be proven to have written nothing.
#[derive(Default)]
struct Operations {
    requests: Mutex<Vec<(String, String, OperationRequest)>>,
}

impl OperationWriter for Operations {
    fn request<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        _resource_version: Option<&'a str>,
        operation: OperationRequest,
    ) -> SeamFuture<'a, ()> {
        Box::pin(async move {
            self.requests
                .lock()
                .map_err(|_| ApiError::backend(&"poisoned test state"))?
                .push((namespace.to_owned(), name.to_owned(), operation));
            Ok(())
        })
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

/// A diff source that returns one `OutOfSync` `Secret`, i.e. the redaction path really runs.
struct SecretsDiff;

impl DiffSource for SecretsDiff {
    fn diff<'a>(&'a self, _app: &'a Application) -> SeamFuture<'a, DiffPreview> {
        Box::pin(async {
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
            let diffs = vec![diff];
            Ok(DiffPreview {
                revision: "8f3a1c2".to_owned(),
                summary: DiffSummary::from_diffs(&diffs),
                desired: diffs.len(),
                would_sync: true,
                diffs,
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

// ---------------------------------------------------------------------------
// The fake `TokenReview`
// ---------------------------------------------------------------------------

/// A `TokenReview` replacement: a token table plus a counter of how many reviews it performed.
///
/// The counter is what makes the cache tests real — "the second request did not call Kubernetes" is
/// only observable if the call is counted.
#[derive(Default)]
struct Tokens {
    identities: BTreeMap<String, AuthenticatedIdentity>,
    reviews: Mutex<Vec<String>>,
    failure: Option<ApiError>,
}

impl Tokens {
    fn with_policy_identities() -> Self {
        Self {
            identities: BTreeMap::from([
                (
                    "team-token".to_owned(),
                    AuthenticatedIdentity::new(TEAM_USER, vec![TEAM_GROUP.to_owned()]),
                ),
                (
                    "admin-token".to_owned(),
                    AuthenticatedIdentity::new(ADMIN_USER, vec![ADMIN_GROUP.to_owned()]),
                ),
                (
                    "tenant-a-token".to_owned(),
                    AuthenticatedIdentity::new(TENANT_A_USER, vec![TENANT_A_GROUP.to_owned()]),
                ),
            ]),
            ..Self::default()
        }
    }

    fn reviews(&self) -> Vec<String> {
        self.reviews.lock().expect("test state").clone()
    }
}

impl TokenAuthenticator for Tokens {
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        self.reviews
            .lock()
            .expect("test state")
            .push(token.to_owned());
        if let Some(failure) = &self.failure {
            return Box::pin(async move { Err(failure.clone()) });
        }
        let identity = self.identities.get(token).cloned();
        Box::pin(async move { Ok(identity) })
    }
}

// ---------------------------------------------------------------------------
// State + HTTP helpers
// ---------------------------------------------------------------------------

fn policy() -> Arc<RbacPolicy> {
    Arc::new(RbacPolicy::parse(POLICY).expect("the documented policy parses"))
}

fn state_with(
    apps: Vec<Application>,
    tokens: Arc<Tokens>,
    policy: Arc<RbacPolicy>,
    cache: IdentityCache,
) -> AppState {
    let project = |name: &str| -> AppProject {
        serde_json::from_value(json!({
            "apiVersion": "ferriscd.io/v1alpha1",
            "kind": "AppProject",
            "metadata": {"name": name, "namespace": "ferriscd-system"},
            "spec": {"destinations": [{"cluster": "in-cluster", "namespace": "*"}]},
        }))
        .expect("a valid AppProject")
    };
    AppState::new(
        Arc::new(Apps(apps)),
        Arc::new(Projects(vec![
            project("payments"),
            project("tenant-a"),
            project("tenant-b"),
        ])),
        Arc::new(Clusters(vec![ClusterEntry {
            name: "in-cluster".to_owned(),
            in_cluster: true,
        }])),
        Arc::new(Operations::default()),
        Arc::new(NoInventory),
        Arc::new(NoGraph),
        Arc::new(SecretsDiff),
        Arc::new(Ready),
    )
    .with_refresh_sink(Arc::new(Sink))
    .with_auth(AuthPolicy::TokenReview)
    .with_token_authenticator(tokens)
    .with_rbac(policy)
    .with_identity_cache(Arc::new(cache))
}

/// The two tenants of the multi-tenancy tests, plus one read-only tenant in `payments`.
fn tenants() -> Vec<Application> {
    vec![
        application("ferriscd-system", "payments-api", "payments"),
        application("ferriscd-system", "tenant-a-api", "tenant-a"),
        application("ferriscd-system", "tenant-b-api", "tenant-b"),
    ]
}

fn state() -> AppState {
    state_with(
        tenants(),
        Arc::new(Tokens::with_policy_identities()),
        policy(),
        IdentityCache::default(),
    )
}

async fn send(
    state: AppState,
    request: Request<Body>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let response = ferriscd_server::router(state)
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()))
    };
    (status, body, headers)
}

fn as_token(request: Request<Body>, token: Option<&str>) -> Request<Body> {
    match token {
        None => request,
        Some(token) => {
            let (mut parts, body) = request.into_parts();
            parts.headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("a header value"),
            );
            Request::from_parts(parts, body)
        }
    }
}

async fn get_as(state: AppState, path: &str, token: Option<&str>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .expect("a request");
    let (status, body, _) = send(state, as_token(request, token)).await;
    (status, body)
}

async fn post_as(
    state: AppState,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("a request");
    let (status, response, _) = send(state, as_token(request, token)).await;
    (status, response)
}

const PROTECTED: [&str; 7] = [
    "/api/v1/applications",
    "/api/v1/applications/ferriscd-system/payments-api",
    "/api/v1/applications/ferriscd-system/payments-api/resources",
    "/api/v1/applications/ferriscd-system/payments-api/diff",
    "/api/v1/projects",
    "/api/v1/clusters",
    "/api/v1/openapi.json",
];

// ---------------------------------------------------------------------------
// T14.3 — TokenReview authentication
// ---------------------------------------------------------------------------

/// **`T14.3` verification:** every protected route is default-deny — a request with no bearer token
/// is `401` in the crate's error shape, with the standard `WWW-Authenticate` challenge.
#[tokio::test]
async fn a_missing_token_is_a_401_on_every_protected_route() {
    for path in PROTECTED {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .expect("a request");
        let (status, body, headers) = send(state(), request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body["error"]["code"], "Unauthorized", "{path}");
        assert_eq!(
            headers.get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer")),
            "{path} must tell the client how to authenticate"
        );
    }
    // A protected POST is refused before its body is even decoded: `401`, not `400`.
    for path in [
        "/api/v1/applications/ferriscd-system/payments-api/sync",
        "/api/v1/applications/ferriscd-system/payments-api/rollback",
    ] {
        let (status, body) = post_as(state(), path, None, json!({"nonsense": true})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body["error"]["code"], "Unauthorized", "{path}");
    }
}

/// **`T14.3` verification:** an invalid token is `401` — and the answer is *identical* to the
/// missing-token answer, so a caller cannot tell "no credential" from "bad credential".
#[tokio::test]
async fn an_invalid_token_is_a_401_and_never_reveals_the_token() {
    let tokens = Arc::new(Tokens::with_policy_identities());
    for token in ["not-a-token", "team-token-but-wrong"] {
        let state = state_with(
            tenants(),
            tokens.clone(),
            policy(),
            IdentityCache::default(),
        );
        let (status, body) = get_as(state, "/api/v1/applications", Some(token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token}");
        assert_eq!(body["error"]["code"], "Unauthorized");
        assert!(
            !body.to_string().contains(token),
            "the refusal must never echo the credential: {body}"
        );
    }
    assert_eq!(
        tokens.reviews().len(),
        2,
        "each unknown token was reviewed once"
    );

    // `Bearer ` with no credential is a malformed header, not something to send to Kubernetes.
    let unreviewed = Arc::new(Tokens::with_policy_identities());
    let state = state_with(
        tenants(),
        unreviewed.clone(),
        policy(),
        IdentityCache::default(),
    );
    let (status, body) = get_as(state.clone(), "/api/v1/applications", Some("")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"]["code"], "Unauthorized");
    assert!(
        unreviewed.reviews().is_empty(),
        "an empty credential must not cost a TokenReview"
    );
    // A non-bearer scheme is refused without a review.
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/applications")
        .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
        .body(Body::empty())
        .expect("a request");
    let (status, _, _) = send(state, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        unreviewed.reviews().is_empty(),
        "another scheme is not a bearer token and is never reviewed"
    );
}

/// **`T14.3` verification:** a valid identity from the `TokenReview` fake reaches the handler and is
/// authorized by its own Kubernetes groups (`T14.4`), i.e. the middleware really resolves and
/// attaches the identity rather than letting the request through anonymously.
#[tokio::test]
async fn a_valid_token_resolves_the_identity_and_authorizes_by_group() {
    let tokens = Arc::new(Tokens::with_policy_identities());
    let state = state_with(
        tenants(),
        tokens.clone(),
        policy(),
        IdentityCache::default(),
    );

    let (status, body) = get_as(state.clone(), "/api/v1/applications", Some("team-token")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["payments-api"],
        "the resolver's group is what the RBAC policy matched: {body}"
    );
    assert_eq!(tokens.reviews(), vec!["team-token".to_owned()]);

    // The same token on a single application it may read.
    let (status, body) = get_as(
        state,
        "/api/v1/applications/ferriscd-system/payments-api",
        Some("team-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["application"]["project"], "payments");
}

/// **`T14.3` verification:** a completed `TokenReview` is cached for 30 s per token, so a polling
/// client costs one review, and a second token costs its own.
#[tokio::test]
async fn a_successful_review_is_cached_for_every_later_request() {
    let tokens = Arc::new(Tokens::with_policy_identities());
    let state = state_with(
        tenants(),
        tokens.clone(),
        policy(),
        IdentityCache::default(),
    );

    for _ in 0..5 {
        let (status, _) = get_as(state.clone(), "/api/v1/applications", Some("team-token")).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        tokens.reviews(),
        vec!["team-token".to_owned()],
        "five requests with one token must cost exactly one TokenReview"
    );

    // A different credential is a different cache key, and a *rejected* credential is never cached
    // (the next request asks Kubernetes again, which is the only way a fresh token can start working).
    let (status, _) = get_as(state.clone(), "/api/v1/applications", Some("admin-token")).await;
    assert_eq!(status, StatusCode::OK);
    for _ in 0..3 {
        let (status, _) = get_as(state.clone(), "/api/v1/applications", Some("bogus")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(
        tokens.reviews(),
        vec![
            "team-token".to_owned(),
            "admin-token".to_owned(),
            "bogus".to_owned(),
            "bogus".to_owned(),
            "bogus".to_owned(),
        ],
        "negatives are not cached: a token Kubernetes just started accepting must work immediately"
    );
}

/// A cache TTL of zero disables caching, which is how the wiring proves the cache is really the
/// thing saving reviews (and not, say, a `OnceCell` in the authenticator).
#[tokio::test]
async fn a_cache_that_is_disabled_reviews_every_request() {
    let tokens = Arc::new(Tokens::with_policy_identities());
    let state = state_with(
        tenants(),
        tokens.clone(),
        policy(),
        IdentityCache::new(Duration::ZERO, 8),
    );
    for _ in 0..3 {
        let (status, _) = get_as(state.clone(), "/api/v1/applications", Some("team-token")).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(tokens.reviews().len(), 3);
}

/// **`T14.3` verification:** a `TokenReview` that *errors* (API server unreachable, RBAC missing) is
/// a `401`. Failing closed is the whole point of an authentication middleware.
#[tokio::test]
async fn a_failed_token_review_refuses_the_request() {
    let tokens = Arc::new(Tokens {
        failure: Some(ApiError::backend(&"the API server is unreachable")),
        ..Tokens::with_policy_identities()
    });
    let state = state_with(tenants(), tokens, policy(), IdentityCache::default());
    let (status, body) = get_as(state, "/api/v1/applications", Some("team-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], "Unauthorized");
    assert!(
        !body.to_string().contains("unreachable"),
        "the backend failure is logged, not published: {body}"
    );
}

/// **`T14.3` verification:** the route groups stay disjoint. Probes carry no credential, a webhook
/// authenticates with its own secret, and only `/api/v1/*` needs a bearer token — so enabling
/// authentication cannot lock out a kubelet probe or a Git server.
#[tokio::test]
async fn the_probes_and_webhooks_are_outside_bearer_authentication() {
    let state = state().with_webhooks(WebhookConfig {
        github_secret: Some(WebhookSecret::new("s3cr3t").expect("secret")),
        debounce: Duration::ZERO,
        max_jitter: Duration::ZERO,
        ..WebhookConfig::default()
    });

    for path in ["/healthz", "/readyz"] {
        let (status, body) = get_as(state.clone(), path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }

    // The protected group in the *same* state is denied: the split is real, not a property of one
    // particular `AppState` configuration.
    let (status, _) = get_as(state.clone(), "/api/v1/applications", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let body = br#"{"ref":"refs/heads/main","repository":{"html_url":"https://github.com/example/payment-service","default_branch":"main"}}"#.to_vec();
    let signature = {
        let digest = webhooks::hmac_sha256(b"s3cr3t", &body);
        let mut signature = String::from("sha256=");
        for byte in digest {
            signature.push_str(&format!("{byte:02x}"));
        }
        signature
    };
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/webhooks/github")
        .header(webhooks::GITHUB_SIGNATURE_HEADER, signature)
        .header(webhooks::GITHUB_DELIVERY_HEADER, "delivery-no-token")
        .header(webhooks::GITHUB_EVENT_HEADER, "push")
        .body(Body::from(body))
        .expect("a request");
    let (status, response, _) = send(state, request).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a webhook authenticates with its secret, never a bearer token: {response}"
    );
}

/// `deny-all` refuses without even looking at the credential, and `pass-through` is the documented
/// development escape (anonymous identity, unrestricted in `T14.4`).
#[tokio::test]
async fn deny_all_and_pass_through_are_the_two_documented_extremes() {
    let locked = state_with(
        tenants(),
        Arc::new(Tokens::with_policy_identities()),
        policy(),
        IdentityCache::default(),
    )
    .with_auth(AuthPolicy::DenyAll);
    let (status, _) = get_as(locked.clone(), "/api/v1/applications", Some("admin-token")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a lockdown refuses even a valid token"
    );
    assert_eq!(get_as(locked, "/healthz", None).await.0, StatusCode::OK);

    // Pass-through: no token, and the empty policy does not matter — this is the dev escape.
    let pass_through = state_with(
        tenants(),
        Arc::new(Tokens::with_policy_identities()),
        Arc::new(RbacPolicy::empty()),
        IdentityCache::default(),
    )
    .with_auth(AuthPolicy::PassThrough);
    let (status, body) = get_as(pass_through, "/api/v1/applications", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["items"].as_array().expect("items").len(),
        3,
        "pass-through is unrestricted by policy: {body}"
    );
}

// ---------------------------------------------------------------------------
// T14.4 — project-scoped RBAC
// ---------------------------------------------------------------------------

/// **`T14.4` verification:** a read-only identity may `get` and `diff`, and is refused (`403`) when
/// it tries to `sync` or `roll back`. Nothing is written when it is refused.
#[tokio::test]
async fn a_read_only_identity_can_read_but_never_mutate() {
    let operations = Arc::new(Operations::default());
    let state = state_with(
        tenants(),
        Arc::new(Tokens::with_policy_identities()),
        policy(),
        IdentityCache::default(),
    );
    // The state above owns its own `Operations`; rebuild with the one this test inspects.
    let state = AppState {
        operations: operations.clone(),
        ..state
    };

    let (status, body) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payments-api",
        Some("team-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payments-api/diff",
        Some("team-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["resources"][0]["key"], "/Secret/payments/db");
    // The diff really is the redacted one: the policy grants `diff`, and the payload it sees is safe.
    assert!(
        !body.to_string().contains("b2xkLXBhc3N3b3Jk"),
        "a read-only or any other identity never sees a Secret value: {body}"
    );

    let (status, body) = post_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payments-api/sync",
        Some("team-token"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "Forbidden");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("sync"),
        "the refusal names the missing action: {body}"
    );

    let (status, body) = post_as(
        state,
        "/api/v1/applications/ferriscd-system/payments-api/rollback",
        Some("team-token"),
        json!({"id": 7}),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(
        operations.requests.lock().expect("state").is_empty(),
        "a refused mutation must never reach the operation writer"
    );
}

/// **`T14.4` verification:** a tenant cannot see another tenant's applications, in the list or by
/// name — and the by-name answer is byte-identical to the answer for an application that does not
/// exist at all (trap guard).
#[tokio::test]
async fn tenant_a_cannot_see_tenant_b_in_a_list_or_by_name() {
    let state = state();

    let (status, body) = get_as(
        state.clone(),
        "/api/v1/applications",
        Some("tenant-a-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let names: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(names, vec!["tenant-a-api"], "{body}");
    assert!(
        !body.to_string().contains("payments-api") && !body.to_string().contains("tenant-b-api"),
        "another tenant's applications must not be in the list: {body}"
    );

    // By name: tenant-b exists, and answers exactly like a name that does not exist.
    let (hidden_status, hidden) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/tenant-b-api",
        Some("tenant-a-token"),
    )
    .await;
    let (missing_status, missing) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/no-such-app",
        Some("tenant-a-token"),
    )
    .await;
    assert_eq!(hidden_status, StatusCode::NOT_FOUND, "{hidden}");
    assert_eq!(
        hidden_status, missing_status,
        "an unauthorized read must not be distinguishable from a missing object"
    );
    assert_eq!(hidden["error"]["code"], missing["error"]["code"]);
    // The message is the *not found* sentence for the requested name — never "forbidden", never a
    // hint that this particular name exists. It is formatted exactly like the missing object's.
    assert_eq!(
        hidden["error"]["message"],
        "Application ferriscd-system/tenant-b-api not found"
    );
    assert_eq!(
        missing["error"]["message"], "Application ferriscd-system/no-such-app not found",
        "the two answers differ only in the name the caller themselves supplied"
    );

    // The same for the diff endpoint: an unauthorized tenant gets the missing-object answer.
    let (hidden_diff, _) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/tenant-b-api/diff",
        Some("tenant-a-token"),
    )
    .await;
    assert_eq!(hidden_diff, StatusCode::NOT_FOUND);

    // And for a mutation the answer is also `404`, not `403`: a tenant with no grant at all must not
    // learn that tenant-b's application exists by trying to sync it.
    let (mutation_status, mutation_body) = post_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/tenant-b-api/sync",
        Some("tenant-a-token"),
        json!({}),
    )
    .await;
    assert_eq!(mutation_status, StatusCode::NOT_FOUND, "{mutation_body}");
    assert_eq!(mutation_body["error"]["code"], "NotFound");

    // The project catalogue is filtered the same way.
    let (status, body) = get_as(state, "/api/v1/projects", Some("tenant-a-token")).await;
    assert_eq!(status, StatusCode::OK);
    let projects: Vec<&str> = body["items"]
        .as_array()
        .expect("items")
        .iter()
        .filter_map(|item| item["name"].as_str())
        .collect();
    assert_eq!(projects, vec!["tenant-a"], "{body}");
}

/// **`T14.4` verification:** the group rule is what authorizes — the username alone is not enough,
/// and a user in no group gets nothing.
#[tokio::test]
async fn group_matching_is_what_authorizes() {
    // `team-token` resolves to TEAM_USER *and* TEAM_GROUP; without the group the policy matches
    // nothing.
    let only_user = Arc::new(Tokens {
        identities: BTreeMap::from([(
            "team-token".to_owned(),
            AuthenticatedIdentity::new(TEAM_USER, Vec::new()),
        )]),
        ..Tokens::default()
    });
    let state = state_with(tenants(), only_user, policy(), IdentityCache::default());
    let (status, body) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payments-api",
        Some("team-token"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "an identity in no group matches no rule: {body}"
    );
    let (status, body) = get_as(state, "/api/v1/applications", Some("team-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().expect("items").len(), 0, "{body}");
}

/// **`T14.4` verification:** an `admin` rule grants every action on every project.
#[tokio::test]
async fn an_admin_rule_can_do_everything_everywhere() {
    let operations = Arc::new(Operations::default());
    let base = state_with(
        tenants(),
        Arc::new(Tokens::with_policy_identities()),
        policy(),
        IdentityCache::default(),
    );
    let state = AppState {
        operations: operations.clone(),
        ..base
    };

    let (status, body) = get_as(state.clone(), "/api/v1/applications", Some("admin-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["items"].as_array().expect("items").len(),
        3,
        "the wildcard rule sees every project: {body}"
    );
    let (status, _) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/tenant-b-api/diff",
        Some("admin-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/tenant-b-api/sync",
        Some("admin-token"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (status, body) = post_as(
        state,
        "/api/v1/applications/ferriscd-system/tenant-b-api/rollback",
        Some("admin-token"),
        json!({"id": 7}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(operations.requests.lock().expect("state").len(), 2);
}

/// **`T14.4` verification (trap guard):** a policy that could not be loaded leaves the API denying
/// every authenticated caller — the *only* safe direction. The binary's fallback is
/// [`ferriscd_server::kube::fallback_to_deny_all`]; a malformed ConfigMap document is exactly the
/// input that reaches it.
#[tokio::test]
async fn a_malformed_policy_fails_closed() {
    let malformed =
        "rules:\n  - subject: {kind: group, name: x}\n    project: payments\n    actions: [read]\n";
    let error = RbacPolicy::parse(malformed).expect_err("`read` is not a documented action");
    let policy = ferriscd_server::kube::fallback_to_deny_all(Err(
        ferriscd_server::kube::RbacLoadError::Invalid {
            namespace: "ferriscd-system".to_owned(),
            name: ferriscd_server::rbac::RBAC_CONFIGMAP_NAME.to_owned(),
            source: error,
        },
    ));
    assert!(policy.is_empty(), "a broken policy must deny everything");

    let state = state_with(
        tenants(),
        Arc::new(Tokens::with_policy_identities()),
        Arc::new(policy),
        IdentityCache::default(),
    );
    // Even a token Kubernetes resolves is refused by the empty policy, on every path.
    let (status, body) = get_as(state.clone(), "/api/v1/applications", Some("admin-token")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().expect("items").len(), 0, "{body}");
    let (status, _) = get_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payments-api",
        Some("admin-token"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = post_as(
        state.clone(),
        "/api/v1/applications/ferriscd-system/payments-api/sync",
        Some("admin-token"),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // The probes stay healthy: the process is up, it just authorizes nobody.
    assert_eq!(get_as(state, "/healthz", None).await.0, StatusCode::OK);
}

/// An `Application` whose project matches a rule the identity holds nothing in is *invisible*, even
/// when a different rule grants the identity `admin` on another project.
#[tokio::test]
async fn a_grant_on_one_project_does_not_leak_into_another() {
    let scoped = Arc::new(
        RbacPolicy::parse(
            r#"
rules:
  - subject: {kind: user, name: system:serviceaccount:ferriscd-system:tenant-a}
    project: tenant-a
    actions: [admin]
"#,
        )
        .expect("a policy"),
    );
    let state = state_with(
        tenants(),
        Arc::new(Tokens::with_policy_identities()),
        scoped,
        IdentityCache::default(),
    );
    let (status, body) = get_as(
        state.clone(),
        "/api/v1/applications",
        Some("tenant-a-token"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"].as_array().expect("items").len(), 1, "{body}");
    let (status, _) = get_as(
        state,
        "/api/v1/applications/ferriscd-system/payments-api",
        Some("tenant-a-token"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
