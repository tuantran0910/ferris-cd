//! `ferriscd-server`: the in-process control-plane API (ADR-002, `T14.1`/`T14.2`).
//!
//! # Why this crate is a library, not a service
//!
//! `Application.status` never stores rendered YAML or a diff (ADR-001), so an endpoint like
//! `GET .../diff` **must** be able to render, read live state and run the SSA dry-run itself. Rather
//! than duplicating the `RepoCache`, renderer cache, `ClusterManager`, `DiscoveryCache` and
//! `DiffEngine` into a second process (or adding Redis, or a new RPC layer — finding C9), this crate
//! is a library that the `ferriscd` binary embeds next to the controller. `ferriscd server` builds
//! one [`ferriscd_controller::ControlPlane`] and hands its collaborators to both:
//!
//! ```text
//!                     ┌──────────────── ferriscd process ────────────────┐
//!   git ──► RepoCache │  controller loop ──► ReconcileContext::pipeline  │
//!                     │        ▲                        │               │
//!   k8s ◄── ClusterManager ─────┼────────────────────────┘               │
//!                     │        │ SyncPipeline::diff (read-only, T14.1)  │
//!   HTTP ──► axum ────┴────────┴── handlers ──► state seams              │
//!                     └───────────────────────────────────────────────────┘
//! ```
//!
//! # Testability
//!
//! Every collaborator is a seam in [`state`]. The router in [`api::router`] takes nothing but an
//! [`AppState`], so the whole API — including the auth split and the webhook hardening — is driven
//! in-process with `tower::ServiceExt::oneshot` and fakes, with no cluster, no Git remote and no
//! network. Production wiring lives in [`kube`].
//!
//! # Security posture of this phase
//!
//! | Layer | What it does |
//! |---|---|
//! | [`auth`] (`T14.3`) | Default-deny `TokenReview` on every protected `/api/v1/*` route; `401` without a valid bearer token. `/healthz`, `/readyz` and `/api/v1/webhooks/*` are separate groups (probes carry no credential; webhooks authenticate with their own secret). |
//! | [`rbac`] (`T14.4`) | Project-scoped `(user\|group, project, action)` policy from `ferriscd-rbac-cm`, deny-by-default; unauthorized reads cannot distinguish "forbidden" from "missing". |
//! | [`webhooks`] (`T14.2`) | Constant-time HMAC/token verification, `X-GitHub-Delivery` replay cache, per-repository debounce. |
//! | Router | A 1 MiB body cap installed before any parsing. |
//! | Everywhere | No payload, log line, or error carries a `Secret` value, a credential, a bearer token, or a webhook secret: diffs come from the engine's only redacting constructor, repository URLs go through `redact_repo_url`, tokens are cached and logged only as a SHA-256 fingerprint, and [`webhooks::WebhookSecret`] redacts its own `Debug`. |
//!
//! `--auth-policy pass-through` is an explicit development escape hatch and logs a warning on a
//! non-loopback bind ([`auth::exposes_unauthenticated_api`]); `--auth-policy deny-all` is a
//! lockdown switch that refuses every protected request without even calling the API server.

pub mod api;
pub mod audit;
pub mod auth;
pub mod error;
pub mod kube;
pub mod openapi;
pub mod rbac;
pub mod state;
pub mod webhooks;

use std::future::Future;
use std::net::SocketAddr;

use axum::Router;

pub use api::router;
pub use audit::{
    AUDIT_SCHEMA_VERSION, AuditActor, AuditCategory, AuditEmitResult, AuditEvent, AuditLogger,
    AuditOutcome, AuditSink, AuditSinkError, AuditTarget, DEFAULT_AUDIT_CHANNEL_CAPACITY,
    JsonlFileAuditSink, REQUEST_ID_HEADER, RecordingAuditSink, RequestId, TokenFingerprint,
    TracingAuditSink, ValidatedAuditWebhookUrl, WebhookAuditSink,
};
pub use auth::{
    AuthPolicy, AuthenticatedIdentity, BearerError, BearerToken, DEFAULT_IDENTITY_CACHE_TTL,
    IdentityCache, TokenAuthenticator, UnconfiguredTokenAuthenticator, UnknownAuthPolicy,
    fingerprint_label, token_fingerprint,
};
pub use error::{ApiError, ApiErrorBody, ApiErrorDetail};
pub use rbac::{
    Action, Actor, DEFAULT_RBAC_NAMESPACE, Grant, RBAC_CONFIGMAP_KEY, RBAC_CONFIGMAP_NAME,
    RbacConfigMapEvent, RbacPolicy, RbacPolicyError, RbacPolicyStore, Rule, SubjectKind,
};
pub use state::{
    AppState, ApplicationSource, ClusterCatalog, ClusterEntry, DiffSource, GraphRequest,
    GraphTraversal, InventoryReader, LiveResourceState, OperationRequest, OperationWriter,
    ProjectCatalog, Readiness, SeamFuture, ServingReadiness, WorkloadGraphSource,
};
pub use webhooks::{FanOut, RefreshSink, RefreshTarget, WebhookConfig, WebhookSecret};

/// Default bind address of the API server (`--api-addr`).
///
/// **Loopback** (`127.0.0.1:8080`). With [`AuthPolicy::TokenReview`] as the default the protected
/// routes are authenticated, so a wider bind is no longer *dangerous* — but publishing an API is a
/// deliberate act, not a default, and loopback costs an operator exactly one `--api-addr` flag (or a
/// `Service` + `kubectl port-forward` while evaluating FerrisCD). The binary warns when a wider bind
/// is combined with the pass-through policy ([`auth::exposes_unauthenticated_api`]).
///
/// Port `8080` is deliberately not `9090`: that is reserved for the `T15.1` metrics listener, so
/// metrics never share a listener with the API.
pub const DEFAULT_API_ADDR: &str = "127.0.0.1:8080";

/// Why the API server stopped.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The listener could not bind (port in use, no permission, bad address).
    #[error("failed to bind the API server to {addr}: {source}")]
    Bind {
        /// The address that was requested.
        addr: String,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },

    /// The server stopped with an I/O error.
    #[error("the API server failed: {source}")]
    Serve {
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
}

/// Serves `state`'s router on `addr` until `shutdown` resolves.
///
/// Graceful shutdown drains in-flight requests (`axum::serve`'s `with_graceful_shutdown`), so a
/// `SIGTERM` that stops the controller and the API together never cuts a diff response in half.
///
/// # Errors
///
/// [`ServeError::Bind`] when the address is unusable, [`ServeError::Serve`] when the accept loop
/// fails.
pub async fn serve<F>(addr: SocketAddr, state: AppState, shutdown: F) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|source| ServeError::Bind {
            addr: addr.to_string(),
            source,
        })?;
    serve_listener(listener, state, shutdown).await
}

/// Serves `state`'s router on an already-bound listener until `shutdown` resolves.
///
/// Split out so a test (or a caller that needs the real port, `:0`) can bind first and read the
/// address afterwards.
///
/// # Errors
///
/// [`ServeError::Serve`] when the accept loop fails.
pub async fn serve_listener<F>(
    listener: tokio::net::TcpListener,
    state: AppState,
    shutdown: F,
) -> Result<(), ServeError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let bound = listener.local_addr().ok();
    let local = bound.map_or_else(|| "<unknown>".to_owned(), |addr| addr.to_string());
    let webhooks_configured = state.webhooks.is_configured();
    tracing::info!(
        addr = %local,
        auth = state.auth.as_str(),
        rbac_rules = state.rbac.rule_count(),
        webhooks_configured,
        debounce = ?state.webhooks.debounce,
        body_limit = state.webhooks.max_body_bytes(),
        "ferriscd-server listening (REST API, OpenAPI, and Git webhooks)"
    );
    // **`T14.4` fail-closed footgun:** `TokenReview` authenticates callers, but an empty RBAC policy
    // authorizes none of them, so every protected request answers `404`/`403` while `healthz` says
    // the server is fine. Say so where the address is known, instead of leaving an operator to
    // discover it from a `403` nobody expected.
    if state.auth == AuthPolicy::TokenReview && state.rbac.is_empty() {
        tracing::warn!(
            auth = state.auth.as_str(),
            configmap = %format!("{}/{}", state.rbac_namespace, rbac::RBAC_CONFIGMAP_NAME),
            key = rbac::RBAC_CONFIGMAP_KEY,
            "the RBAC policy is EMPTY (default-deny): every authenticated request will be refused \
             unless a policy rule grants it. Publish the `{}` ConfigMap in the control-plane \
             namespace (default `{}`) with a `{}` document",
            rbac::RBAC_CONFIGMAP_NAME,
            state.rbac_namespace,
            rbac::RBAC_CONFIGMAP_KEY,
        );
    }
    // **Finding `P14-H1`:** pass-through cannot authenticate anybody, so a bind that anyone but the
    // pod itself can reach would expose every `/api/v1/*` route — sync and rollback included — to
    // any workload on the cluster network. Warn where the combination is decided and the real
    // address is known, so it is logged even when the process is not started through `ferriscd
    // server` (which is the only place that parses `--auth-policy`).
    if let Some(addr) = bound
        && auth::exposes_unauthenticated_api(addr, state.auth)
    {
        tracing::warn!(
            addr = %addr,
            auth = state.auth.as_str(),
            "the protected API is UNAUTHENTICATED: --auth-policy=pass-through (a development \
             escape hatch) is serving /api/v1/* on a non-loopback address, so any client that can \
             reach it can read diffs and request syncs/rollbacks. Drop --auth-policy to use the \
             default TokenReview authentication, or bind --api-addr to 127.0.0.1"
        );
    }
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|source| ServeError::Serve { source })
}

/// Builds the router from a state (a convenience alias for [`api::router`]).
pub fn app(state: AppState) -> Router {
    api::router(state)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::state::NotReady;

    /// **Finding `P14-H1`:** the default bind is loopback (publishing an API is a deliberate act)
    /// and it is not the metrics port. With `T14.3`'s `TokenReview` default the shipped combination
    /// is authenticated *and* unreachable from the cluster network.
    #[test]
    fn the_default_address_is_loopback_and_not_the_metrics_port() {
        let addr: SocketAddr = DEFAULT_API_ADDR.parse().expect("a valid socket address");
        assert_eq!(addr.port(), 8080);
        assert_ne!(addr.port(), 9090, ":9090 is the T15.1 metrics listener");
        // `T15.1`: the metrics listener really is a *different* socket, so `/metrics` is never
        // routed by this crate's API router (it lives in `ferriscd-controller`).
        let metrics: SocketAddr = ferriscd_controller::DEFAULT_METRICS_ADDR
            .parse()
            .expect("the metrics default is a socket address");
        assert_eq!(metrics.port(), 9090);
        assert_ne!(metrics, addr, "the two listeners must never share a port");
        assert!(
            addr.ip().is_loopback(),
            "the default bind must stay on loopback: {addr}"
        );
        assert_eq!(
            AuthPolicy::default(),
            AuthPolicy::TokenReview,
            "the shipped default must authenticate every protected request"
        );
        assert!(
            !crate::auth::exposes_unauthenticated_api(addr, AuthPolicy::default()),
            "the shipped default must not be the warned-about combination: {addr}"
        );
    }

    /// Binding on `:0` and reading the address back is what makes a real HTTP test hermetic.
    #[tokio::test]
    async fn a_listener_can_be_served_and_shut_down() {
        let state = crate::tests_support::state(Arc::new(NotReady));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a free port");
        let addr = listener.local_addr().expect("an address");
        let shutdown = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_listener(listener, state, async move {
            let _ = shutdown.1.await;
        }));

        // The health probe answers over a real socket.
        let response = reqwest_like_get(addr, "/healthz").await;
        assert_eq!(response, 200);

        shutdown.0.send(()).expect("shutdown is signalled");
        server
            .await
            .expect("the server joins")
            .expect("no serve error");
    }

    /// A minimal HTTP/1.1 GET, so this test needs no HTTP client dependency.
    async fn reqwest_like_get(addr: SocketAddr, path: &str) -> u16 {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .expect("write");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        let text = String::from_utf8_lossy(&response);
        text.split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .expect("a status line")
    }
}

/// Test helpers shared by the crate's unit tests (never compiled into a release build).
#[cfg(test)]
pub(crate) mod tests_support {
    use std::sync::Arc;

    use ferriscd_controller::DiffPreview;
    use ferriscd_crd::Application;
    use ferriscd_engine::diff::DiffSummary;

    use super::state::{
        AppState, ApplicationSource, ClusterCatalog, DiffSource, InventoryReader, OperationWriter,
        ProjectCatalog, Readiness, SeamFuture, WorkloadGraphSource,
    };

    pub(crate) struct NoApplications;
    impl ApplicationSource for NoApplications {
        fn list(&self) -> SeamFuture<'_, Vec<Application>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn get(&self, _namespace: &str, _name: &str) -> SeamFuture<'_, Option<Application>> {
            Box::pin(async { Ok(None) })
        }
    }

    pub(crate) struct NoProjects;
    impl ProjectCatalog for NoProjects {
        fn list(&self) -> SeamFuture<'_, Vec<ferriscd_crd::AppProject>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    pub(crate) struct NoClusters;
    impl ClusterCatalog for NoClusters {
        fn list(&self) -> Vec<super::state::ClusterEntry> {
            Vec::new()
        }
    }

    pub(crate) struct NoOperations;
    impl OperationWriter for NoOperations {
        fn request<'a>(
            &'a self,
            _namespace: &'a str,
            _name: &'a str,
            _resource_version: Option<&'a str>,
            _operation: super::state::OperationRequest,
        ) -> SeamFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    pub(crate) struct NoInventory;
    impl InventoryReader for NoInventory {
        fn read<'a>(
            &'a self,
            _app: &'a Application,
        ) -> SeamFuture<'a, Vec<super::state::LiveResourceState>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    pub(crate) struct NoGraph;
    impl WorkloadGraphSource for NoGraph {
        fn children(
            &self,
            _traversal: &super::state::GraphTraversal,
            _parent: &super::state::GraphRequest<'_>,
        ) -> SeamFuture<'_, Vec<super::state::ChildNode>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    pub(crate) struct EmptyDiff;
    impl DiffSource for EmptyDiff {
        fn diff<'a>(&'a self, _app: &'a Application) -> SeamFuture<'a, DiffPreview> {
            Box::pin(async {
                Ok(DiffPreview {
                    revision: "deadbeef".to_owned(),
                    diffs: Vec::new(),
                    summary: DiffSummary::default(),
                    desired: 0,
                    would_sync: false,
                })
            })
        }
    }

    pub(crate) fn state(readiness: Arc<dyn Readiness>) -> AppState {
        AppState::new(
            Arc::new(NoApplications),
            Arc::new(NoProjects),
            Arc::new(NoClusters),
            Arc::new(NoOperations),
            Arc::new(NoInventory),
            Arc::new(NoGraph),
            Arc::new(EmptyDiff),
            readiness,
        )
    }
}
