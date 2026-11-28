//! The seams the control-plane API talks to, and the shared state every handler receives.
//!
//! The server owns **no** cache and **no** cluster connection of its own (finding C9): every seam
//! below is implemented in-process over the collaborators [`ferriscd_controller::ControlPlane`]
//! already built, so `GET .../diff` and `GET .../resources` compute live answers through the very
//! same `RepoCache`, renderer cache, `ClusterManager`, `DiscoveryCache` and `DiffEngine` the next
//! reconcile uses.
//!
//! The traits exist so the *entire* router is testable with `tower::ServiceExt::oneshot` and no
//! cluster: a test substitutes a fake source/pipeline and asserts the response. Production wiring is
//! [`crate::kube`] (one thin adapter per trait).

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ferriscd_crd::{AppProject, Application};
use ferriscd_engine::manifest::ResourceKey;
use futures::future::BoxFuture;
use futures::stream::BoxStream;

use crate::audit::AuditLogger;
use crate::auth::{AuthPolicy, IdentityCache, TokenAuthenticator, UnconfiguredTokenAuthenticator};
use crate::error::ApiError;
use crate::rbac::{RbacPolicy, RbacPolicyStore};
use crate::webhooks::{DeliveryDedupe, FanOut, RefreshSink, WebhookConfig};

/// A boxed fallible future, so the seams stay object-safe.
pub type SeamFuture<'a, T> = BoxFuture<'a, Result<T, ApiError>>;

/// How many namespace-scoped `list` calls **one** `GET .../resources` request may issue.
///
/// The endpoint's cost is otherwise a function of the caller's cluster: one listing per traversed
/// workload is `O(deployments)` sequential API calls, which a large application (or a caller who
/// opens the graph in a loop) turns into a request storm against the API server (finding `P14-H2`).
/// The traversal caches per `(cluster, namespace, kind)`, so a normal application needs two
/// listings; this is the hard ceiling for a pathological one, and the response reports
/// `truncated: true` when it is reached.
pub const MAX_GRAPH_LIST_REQUESTS: usize = 16;

/// The `ListParams::limit` of each of those listings.
///
/// A namespace with 10 000 pods must not be able to make one HTTP request allocate 10 000 nodes:
/// the listing is bounded, and everything discovered from it is bounded again by
/// [`crate::api::MAX_GRAPH_NODES`].
pub const GRAPH_LIST_LIMIT: u32 = 500;

/// One object discovered by a namespace-scoped `list`, reduced to what owner matching needs.
///
/// Deliberately not the object body: the traversal only ever compares
/// `metadata.ownerReferences`, and holding whole `Pod`s would multiply the memory a single request
/// needs by the size of the namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedNode {
    /// `metadata.name` of the child.
    pub name: String,
    /// `(kind, name)` of every `metadata.ownerReferences` entry.
    pub owners: Vec<(String, String)>,
}

impl ListedNode {
    /// Builds a node from a name and its `metadata.ownerReferences`.
    pub fn new(name: impl Into<String>, owners: Vec<(String, String)>) -> Self {
        Self {
            name: name.into(),
            owners,
        }
    }

    /// Whether this node is owned by `kind` `name`.
    #[must_use]
    pub fn owned_by(&self, kind: &str, name: &str) -> bool {
        self.owners
            .iter()
            .any(|(owner_kind, owner_name)| owner_kind == kind && owner_name == name)
    }
}

/// The `(cluster, namespace, kind)` one listing answers — the per-request cache key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ListKey {
    cluster: String,
    namespace: String,
    kind: &'static str,
}

impl ListKey {
    pub(crate) fn new(cluster: &str, namespace: &str, kind: &'static str) -> Self {
        Self {
            cluster: cluster.to_owned(),
            namespace: namespace.to_owned(),
            kind,
        }
    }
}

/// One `GET .../resources` traversal: its listing cache and its request-wide read budget.
///
/// The handler builds exactly one per request, which is what makes `Deployment -> ReplicaSet -> Pod`
/// cost **one** `ReplicaSet` list plus **one** `Pod` list per `(cluster, namespace)` however many
/// workloads the application owns — instead of re-listing the same namespace once per workload
/// (finding `P14-H2`). Nothing is shared between requests: the next request re-reads the cluster,
/// because a cached listing is exactly the stale live state ADR-004 forbids.
#[derive(Debug)]
pub struct GraphTraversal {
    id: u64,
    listings: Mutex<BTreeMap<ListKey, Arc<Vec<ListedNode>>>>,
    issued: AtomicUsize,
    exhausted: AtomicBool,
}

impl Default for GraphTraversal {
    fn default() -> Self {
        Self::new()
    }
}

impl GraphTraversal {
    /// Starts a traversal for one request.
    #[must_use]
    pub fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            listings: Mutex::new(BTreeMap::new()),
            issued: AtomicUsize::new(0),
            exhausted: AtomicBool::new(false),
        }
    }

    /// A stable identity for this request's traversal.
    ///
    /// Only for correlation (the budget warning names it) and for asserting in a test that one
    /// request shares one traversal: it is never sent to a client and never persisted.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// How many cluster `list` calls this request has issued so far.
    #[must_use]
    pub fn listings_issued(&self) -> usize {
        self.issued.load(Ordering::SeqCst)
    }

    /// Whether the request-wide budget cut the traversal short.
    ///
    /// The handler reports this as `truncated`, so a response that stopped early never looks
    /// complete.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::SeqCst)
    }

    /// The cached listing for `key`, issuing `list` **at most once** per request.
    ///
    /// `list` is only called on a cache miss (a cache hit costs one map lookup, never an API call).
    /// `Ok(None)` means the request's listing budget is spent: this parent reports no children and
    /// [`Self::is_exhausted`] becomes true.
    pub(crate) async fn listing<F, Fut>(
        &self,
        key: ListKey,
        list: F,
    ) -> Result<Option<Arc<Vec<ListedNode>>>, ApiError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<ListedNode>, ApiError>>,
    {
        if let Some(cached) = self.cached(&key) {
            return Ok(Some(cached));
        }
        if !self.charge() {
            return Ok(None);
        }
        let listed = Arc::new(list().await?);
        let mut listings = self.lock();
        listings.insert(key, Arc::clone(&listed));
        Ok(Some(listed))
    }

    fn cached(&self, key: &ListKey) -> Option<Arc<Vec<ListedNode>>> {
        self.lock().get(key).map(Arc::clone)
    }

    /// Charges one listing to the request budget; `false` when it is spent.
    fn charge(&self) -> bool {
        let mut current = self.issued.load(Ordering::SeqCst);
        loop {
            if current >= MAX_GRAPH_LIST_REQUESTS {
                self.exhausted.store(true, Ordering::SeqCst);
                return false;
            }
            match self.issued.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<ListKey, Arc<Vec<ListedNode>>>> {
        // A poisoned listing cache is still usable: the worst case is one extra cluster read.
        self.listings.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Reads `Application` objects (`GET /api/v1/applications[/ns/name]`, operation handlers, and the
/// webhook matcher).
///
/// Reads only: the API never mutates an `Application` except through
/// [`OperationWriter`] (`ferriscd.io/operation`) and [`RefreshSink`] (`ferriscd.io/refresh`), and
/// both patch annotations instead of spec/status so a manual request can never fight the
/// always-update-status contract.
pub trait ApplicationSource: Send + Sync + 'static {
    /// Lists every `Application` this control plane watches.
    fn list(&self) -> SeamFuture<'_, Vec<Application>>;

    /// Reads one `Application`, or `Ok(None)` when it does not exist.
    fn get(&self, namespace: &str, name: &str) -> SeamFuture<'_, Option<Application>>;
}

/// Reads `AppProject` objects (`GET /api/v1/projects`, and the sync-window verdict of
/// `GET /api/v1/applications/{namespace}/{name}`).
pub trait ProjectCatalog: Send + Sync + 'static {
    /// Lists every `AppProject` of the control-plane namespace.
    fn list(&self) -> SeamFuture<'_, Vec<AppProject>>;

    /// Reads one `AppProject`, or `Ok(None)` when it does not exist (finding M-4).
    ///
    /// The application-detail path needs exactly one project — the one its `spec.project` names — so
    /// it must not list (and deserialize) the whole catalogue to find it. The default implementation
    /// is that listing, which keeps every test fake honest without an extra method; the production
    /// adapter ([`crate::kube::KubeProjectCatalog`]) overrides it with a single `Api::get_opt`.
    fn get(&self, name: &str) -> SeamFuture<'_, Option<AppProject>> {
        let name = name.to_owned();
        Box::pin(async move {
            Ok(self
                .list()
                .await?
                .into_iter()
                .find(|project| project.metadata.name.as_deref() == Some(name.as_str())))
        })
    }
}

/// The most Kubernetes `Event`s one `GET .../events` response carries (`T17.3`).
///
/// A namespace keeps Events for roughly an hour and a long-failing `Application` can accumulate
/// hundreds of them, so the response is a bounded *timeline* (the latest 50, newest first) instead
/// of a dump: the UI renders one screenful and `truncated` says the rest exists.
pub const MAX_APPLICATION_EVENTS: usize = 50;

/// One Kubernetes `events.k8s.io/v1` `Event` about an `Application`, reduced to a timeline entry.
///
/// `note` is deliberately carried **unredacted** here: [`crate::api`] runs every note through
/// `ferriscd_controller::events::sanitize_note` (URL credentials, embedded secret payloads, 1 KiB
/// cap) so a new [`EventSource`] implementation cannot bypass redaction by forgetting to call it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplicationEvent {
    /// `metadata.name` of the `Event`.
    pub name: String,
    /// `type`: `Normal`, `Warning`, or `Unknown` when the field is absent.
    pub event_type: String,
    /// `reason` — a machine-readable, bounded label (`SyncSucceeded`, `SyncFailed`, ...).
    pub reason: String,
    /// `note` — the human-readable message, **not yet redacted** (see the type docs).
    pub note: String,
    /// `action` (`Sync`, `Prune`, ...).
    pub action: Option<String>,
    /// `series.count` (or `deprecatedCount`): how many times the event recurred.
    pub count: i32,
    /// `reportingController` — the component that emitted the event.
    pub reporting_component: Option<String>,
    /// When the event was last observed, as RFC 3339 UTC.
    pub last_observed_at: Option<String>,
    /// When the event was first observed, as RFC 3339 UTC.
    pub first_observed_at: Option<String>,
}

/// Reads the Kubernetes `Event`s that regard one `Application` (`GET .../events`, `T17.3`).
///
/// The one thing every implementation must get right is the **scope**: an implementation has to
/// query `events.k8s.io/v1` `Event`s in the `Application`'s own namespace, filtered server-side by
/// `regarding.uid`, and must never fall back to a namespace-wide or cluster-wide listing (trap
/// guard). `ferriscd-server`'s own adapter (`crate::kube::KubeEventSource`) refuses to query at all
/// when the `Application` has no `metadata.uid`.
pub trait EventSource: Send + Sync + 'static {
    /// The latest events about `app`, newest first, at most [`MAX_APPLICATION_EVENTS`].
    fn list<'a>(&'a self, app: &'a Application) -> SeamFuture<'a, Vec<ApplicationEvent>>;
}

/// No event source is configured: the timeline is empty.
///
/// This is the default for a state built without one (tests, and any embedder that does not want
/// the endpoint). It answers "no events", never an error, so a partially wired control plane still
/// serves every other page.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvents;

impl EventSource for NoEvents {
    fn list<'a>(&'a self, _app: &'a Application) -> SeamFuture<'a, Vec<ApplicationEvent>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// Streams `Application` snapshots for the SSE dashboard feed (`GET /api/v1/applications/stream`).
///
/// # Why a stream of *snapshots*
///
/// A control plane has no event log to replay: the authoritative answer to "what changed" is always
/// "re-read the `Application`s". Each item is therefore a complete, caller-filtered snapshot that the
/// UI replaces its list with, which makes a missed or dropped frame harmless — the next snapshot
/// repairs it. That is also why the feed never carries another tenant's object: the handler filters
/// every snapshot through the live RBAC policy before it is written to the socket.
///
/// # Boundedness and cleanup
///
/// Implementations share one refresher across subscribers: the stream carries the latest snapshot
/// (a slow client skips frames rather than growing a queue), and the refresher stops when the last
/// subscription is dropped. A client disconnect therefore costs no further cluster reads.
pub trait ApplicationSnapshotSource: Send + Sync + 'static {
    /// Opens one subscription for one connection.
    fn subscribe(&self) -> BoxStream<'static, Result<Vec<Application>, ApiError>>;
}

/// No snapshot feed is configured: the stream ends immediately.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSnapshots;

impl ApplicationSnapshotSource for NoSnapshots {
    fn subscribe(&self) -> BoxStream<'static, Result<Vec<Application>, ApiError>> {
        Box::pin(futures::stream::empty())
    }
}

/// One registered cluster, as `GET /api/v1/clusters` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterEntry {
    /// `spec.destination.cluster` name (`in-cluster` for the control plane's own cluster).
    pub name: String,
    /// Whether this is the cluster the control plane runs in.
    pub in_cluster: bool,
}

/// Lists the cluster registry (`GET /api/v1/clusters`, `T13.1`).
pub trait ClusterCatalog: Send + Sync + 'static {
    /// Every addressable cluster name, `in-cluster` first.
    fn list(&self) -> Vec<ClusterEntry>;
}

/// A manual operation the API can request (`POST .../sync`, `POST .../rollback`).
///
/// Only the documented `ferriscd.io/operation` payloads exist; the controller parses them and the
/// **controller** decides what happens (the API never syncs anything itself).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationRequest {
    /// `{"sync":{}}`: reconcile now, even with `syncPolicy.automated` unset.
    Sync,
    /// `{"rollback":{"id":N}}`: redeploy the commit recorded for history entry `N`.
    Rollback {
        /// `status.history[].id` to redeploy.
        id: i64,
    },
}

impl OperationRequest {
    /// The exact annotation value the controller parses (`ferriscd.io/operation`).
    ///
    /// The JSON is canonical: `{"sync":{}}` carries no `rollback` key, so
    /// `ferriscd_engine::sync::parse_rollback_request` reports `NotARollback` and the reconcile
    /// treats it as the documented manual-sync request; a rollback carries exactly
    /// `{"rollback":{"id":N}}`.
    #[must_use]
    pub fn annotation_value(&self) -> String {
        match self {
            Self::Sync => r#"{"sync":{}}"#.to_owned(),
            Self::Rollback { id } => format!(r#"{{"rollback":{{"id":{id}}}}}"#),
        }
    }

    /// A stable label for responses and logs.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Rollback { .. } => "rollback",
        }
    }
}

/// Patches `ferriscd.io/operation` onto an `Application` (`T14.1`).
pub trait OperationWriter: Send + Sync + 'static {
    /// Requests `operation` on `namespace/name`.
    ///
    /// `resource_version` is the compare-and-swap precondition: when the object changed since it was
    /// read, the write fails with [`ApiError::Conflict`] instead of overwriting a request somebody
    /// else just made.
    fn request<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        resource_version: Option<&'a str>,
        operation: OperationRequest,
    ) -> SeamFuture<'a, ()>;
}

/// One resource of `status.inventory`, as the live cluster sees it right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveResourceState {
    /// Version-agnostic GKNN key (`group/kind/namespace/name`).
    pub key: ResourceKey,
    /// Whether the object exists in the destination cluster right now.
    pub present: bool,
    /// Ownership verdict for a present object: `OwnedBySelf`, `Unmanaged`, or `OwnedByForeign`.
    pub ownership: Option<&'static str>,
}

/// Reads the live state of an `Application`'s inventory (`GET .../resources`).
///
/// **On demand, never an informer** (ADR-004): a request costs one scoped read per inventory key on
/// the destination cluster and nothing is cached between requests.
pub trait InventoryReader: Send + Sync + 'static {
    /// Reads every key of `app.status.inventory` for `app`.
    fn read<'a>(&'a self, app: &'a Application) -> SeamFuture<'a, Vec<LiveResourceState>>;
}

/// One child discovered by `metadata.ownerReferences` traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildNode {
    /// GKNN of the child.
    pub key: ResourceKey,
    /// The cluster the child was read from (`spec.destination.cluster`).
    pub cluster: String,
}

/// The parent whose children are requested.
#[derive(Debug, Clone, Copy)]
pub struct GraphRequest<'a> {
    /// Destination cluster (`spec.destination.cluster`).
    pub cluster: &'a str,
    /// Namespace of the parent object (always `spec.destination.namespace` for a workload).
    pub namespace: &'a str,
    /// Parent kind (`Deployment`, `ReplicaSet`, `StatefulSet`, ...).
    pub kind: &'a str,
    /// Parent name.
    pub name: &'a str,
}

/// Lists the live children of one workload node (`Deployment -> ReplicaSet -> Pod`, `T14.1`).
pub trait WorkloadGraphSource: Send + Sync + 'static {
    /// Lists the children of `parent` through `metadata.ownerReferences`.
    ///
    /// `traversal` is **one request's** scope: an implementation must cache its cluster reads on it,
    /// so a request that walks twenty `Deployment`s lists the namespace's `ReplicaSet`s once, not
    /// twenty times, and must respect its listing budget (finding `P14-H2`).
    ///
    /// A kind with no children (a `ConfigMap`, a `Service`) returns an empty list, never an error.
    fn children<'a>(
        &'a self,
        traversal: &'a GraphTraversal,
        parent: &GraphRequest<'_>,
    ) -> SeamFuture<'a, Vec<ChildNode>>;
}

/// Computes the live, Secret-redacted diff of an `Application` (`GET .../diff`).
pub trait DiffSource: Send + Sync + 'static {
    /// Returns the diff preview.
    ///
    /// The preview is the read-only prefix of a reconcile, so a refusal here is the same refusal the
    /// next sync would report (`PolicyViolation`, a bad revision, an unreachable cluster).
    fn diff<'a>(&'a self, app: &'a Application)
    -> SeamFuture<'a, ferriscd_controller::DiffPreview>;
}

/// Reports whether the API server should receive traffic (`GET /readyz`).
pub trait Readiness: Send + Sync + 'static {
    /// Whether the process is ready.
    fn is_ready(&self) -> bool;

    /// Why it is not ready (secret-free), for the `/readyz` body.
    fn reason(&self) -> Option<String> {
        None
    }
}

/// Always ready: the API is serving and nothing else is known yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct ServingReadiness;

impl Readiness for ServingReadiness {
    fn is_ready(&self) -> bool {
        true
    }
}

/// Never ready: used to prove `/readyz` really gates traffic on the seam.
#[derive(Debug, Clone, Copy, Default)]
pub struct NotReady;

impl Readiness for NotReady {
    fn is_ready(&self) -> bool {
        false
    }

    fn reason(&self) -> Option<String> {
        Some("the control-plane watches have not completed their initial list".to_owned())
    }
}

/// The secret-free facts `GET /api/v1/auth/config` publishes to the Web UI and the CLI (`T19.1`).
///
/// Deliberately not the [`crate::oidc::OidcConfig`]: this type is what an **unauthenticated** caller
/// may learn, so it carries no CA bundle, no secret and no prefix that would let an IdP claim be
/// forged offline. `bff_enabled` is published now and wired by `T19.2` (the cookie session flow).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublicAuthConfig {
    /// The configured issuer, when OIDC is enabled.
    pub issuer: Option<String>,
    /// The configured OAuth client id, when OIDC is enabled.
    pub client_id: Option<String>,
    /// The scopes the SPA/CLI should request.
    pub scopes: Vec<String>,
    /// Whether the optional server-side (BFF cookie) session mode is available (`T19.2`).
    pub bff_enabled: bool,
}

impl PublicAuthConfig {
    /// The OIDC facts for `issuer` + `client_id`.
    #[must_use]
    pub fn oidc(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            issuer: Some(issuer.into()),
            client_id: Some(client_id.into()),
            scopes,
            bff_enabled: false,
        }
    }
}

/// Everything the router needs.
///
/// Deliberately a bag of seams: one `AppState` is built by [`crate::Server`] from the shared
/// [`ferriscd_controller::ControlPlane`], and a test builds one from fakes — the handlers cannot
/// tell the difference, which is what makes the whole API testable without a cluster.
#[derive(Clone)]
pub struct AppState {
    /// `Application` reads.
    pub applications: Arc<dyn ApplicationSource>,
    /// `AppProject` reads.
    pub projects: Arc<dyn ProjectCatalog>,
    /// Kubernetes `Event` reads for the `Application` events timeline (`T17.3`).
    pub events: Arc<dyn EventSource>,
    /// The SSE snapshot feed (`GET /api/v1/applications/stream`, `T17.3`).
    pub snapshots: Arc<dyn ApplicationSnapshotSource>,
    /// The cluster registry.
    pub clusters: Arc<dyn ClusterCatalog>,
    /// `ferriscd.io/operation` writes.
    pub operations: Arc<dyn OperationWriter>,
    /// Live inventory reads.
    pub inventory: Arc<dyn InventoryReader>,
    /// `metadata.ownerReferences` traversal.
    pub graph: Arc<dyn WorkloadGraphSource>,
    /// Live diff computation.
    pub diffs: Arc<dyn DiffSource>,
    /// `/readyz`.
    pub readiness: Arc<dyn Readiness>,
    /// `T14.3` authentication policy (`TokenReview` by default).
    pub auth: AuthPolicy,
    /// `T14.3` bearer-token validator (`TokenReview` in production).
    pub tokens: Arc<dyn TokenAuthenticator>,
    /// `T14.3` positive-only `TokenReview` cache, keyed by token SHA-256.
    pub identities: Arc<IdentityCache>,
    /// `T19.1` secret-free OIDC facts `GET /api/v1/auth/config` publishes.
    pub auth_config: PublicAuthConfig,
    /// `T19.2` optional server-side (BFF) session flow. `None` = the SPA does its own PKCE flow.
    pub bff: Option<Arc<crate::auth_bff::BffState>>,
    /// `T14.4` / `T17.1` live-reloading project-scoped authorization policy store (empty = deny
    /// every authenticated caller).
    pub rbac: RbacPolicyStore,
    /// Control-plane namespace the RBAC `ConfigMap` is read from (`--namespace`).
    pub rbac_namespace: String,
    /// `T14.2` webhook configuration (secrets, caps, debounce).
    pub webhooks: WebhookConfig,
    /// `T14.2` bounded replay cache for `X-GitHub-Delivery` ids.
    pub dedupe: Arc<DeliveryDedupe>,
    /// The `ferriscd.io/refresh` writer the webhook fan-out uses.
    pub refreshes: Arc<dyn RefreshSink>,
    /// Per-repository debounce + jittered fan-out (`T14.2`).
    pub fan_out: Arc<FanOut>,
    /// Compliance audit logger (`T17.2`): lossless stdout JSON (`ferriscd::audit`) plus optional
    /// non-blocking file/webhook sinks.
    pub audit: AuditLogger,
}

impl fmt::Debug for AppState {
    /// Never prints a webhook secret, an application object, or a diff: this type is cloned into
    /// every request and a stray `{:?}` must stay safe.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("auth", &self.auth)
            .field("identities", &self.identities)
            .field("rbac_rules", &self.rbac.rule_count())
            .field("webhooks", &self.webhooks)
            .field("readiness", &self.readiness.is_ready())
            .field("bff_enabled", &self.bff.is_some())
            .finish_non_exhaustive()
    }
}

impl AppState {
    /// Builds a state from explicit seams (production: [`AppState::from_control_plane`]).
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        applications: Arc<dyn ApplicationSource>,
        projects: Arc<dyn ProjectCatalog>,
        clusters: Arc<dyn ClusterCatalog>,
        operations: Arc<dyn OperationWriter>,
        inventory: Arc<dyn InventoryReader>,
        graph: Arc<dyn WorkloadGraphSource>,
        diffs: Arc<dyn DiffSource>,
        readiness: Arc<dyn Readiness>,
    ) -> Self {
        let webhooks = WebhookConfig::default();
        let dedupe = Arc::new(DeliveryDedupe::new(
            webhooks.dedupe_capacity,
            webhooks.dedupe_ttl,
        ));
        let refreshes: Arc<dyn RefreshSink> = Arc::new(crate::webhooks::UnconfiguredRefreshSink);
        let fan_out = Arc::new(FanOut::new(&webhooks, refreshes.clone()));
        Self {
            applications,
            projects,
            events: Arc::new(NoEvents),
            snapshots: Arc::new(NoSnapshots),
            clusters,
            operations,
            inventory,
            graph,
            diffs,
            readiness,
            auth: AuthPolicy::default(),
            tokens: Arc::new(UnconfiguredTokenAuthenticator),
            identities: Arc::new(IdentityCache::default()),
            auth_config: PublicAuthConfig::default(),
            bff: None,
            rbac: RbacPolicyStore::empty(),
            rbac_namespace: crate::rbac::DEFAULT_RBAC_NAMESPACE.to_owned(),
            webhooks,
            dedupe,
            refreshes,
            fan_out,
            audit: AuditLogger::default(),
        }
    }

    /// Replaces the webhook configuration (and rebuilds the fan-out around it).
    #[must_use]
    pub fn with_webhooks(mut self, webhooks: WebhookConfig) -> Self {
        self.fan_out = Arc::new(FanOut::new(&webhooks, self.refreshes.clone()));
        self.dedupe = Arc::new(DeliveryDedupe::new(
            webhooks.dedupe_capacity,
            webhooks.dedupe_ttl,
        ));
        self.webhooks = webhooks;
        self
    }

    /// Replaces the `ferriscd.io/refresh` writer.
    #[must_use]
    pub fn with_refresh_sink(mut self, refreshes: Arc<dyn RefreshSink>) -> Self {
        self.fan_out = Arc::new(FanOut::new(&self.webhooks, refreshes.clone()));
        self.refreshes = refreshes;
        self
    }

    /// Replaces the authentication seam.
    ///
    /// **Finding `N4a`:** an [`AuthPolicy::Oidc`] or [`AuthPolicy::TokenReviewOrOidc`] policy must be
    /// paired with [`Self::with_auth_config`] (built by [`PublicAuthConfig::oidc`]). The policy is
    /// what `GET /api/v1/auth/config` publishes as `authMode`, so an `oidc` policy with no issuer
    /// and no client id tells every Web UI and CLI to start an SSO sign-in it cannot complete.
    ///
    /// The binary cannot reach that state — `--oidc-issuer` and `--oidc-client-id` are required for
    /// an OIDC policy and the server refuses to start without them — but a library embedder builds
    /// an `AppState` by hand. [`Self::auth_config_matches_policy`] is the predicate the discovery
    /// handler `debug_assert!`s, so the mismatch fails in tests rather than in a browser; call
    /// either builder in either order, but call both.
    #[must_use]
    pub fn with_auth(mut self, auth: AuthPolicy) -> Self {
        self.auth = auth;
        self
    }

    /// Replaces the bearer-token validator (`T14.3`).
    #[must_use]
    pub fn with_token_authenticator(mut self, tokens: Arc<dyn TokenAuthenticator>) -> Self {
        self.tokens = tokens;
        self
    }

    /// Replaces the positive `TokenReview` cache (a test uses a zero TTL to count reviews).
    #[must_use]
    pub fn with_identity_cache(mut self, identities: Arc<IdentityCache>) -> Self {
        self.identities = identities;
        self
    }

    /// Publishes the secret-free OIDC facts on `GET /api/v1/auth/config` (`T19.1`).
    ///
    /// Required whenever [`Self::with_auth`] selected an OIDC policy (finding `N4a`): see
    /// [`Self::auth_config_matches_policy`].
    #[must_use]
    pub fn with_auth_config(mut self, auth_config: PublicAuthConfig) -> Self {
        self.auth_config = auth_config;
        self
    }

    /// Enables the optional server-side (BFF) session flow (`T19.2`).
    ///
    /// Turns on `GET /api/v1/auth/login`, `GET /api/v1/auth/callback`, `POST /api/v1/auth/logout`, the
    /// CSRF middleware on mutating routes, cookie authentication in [`crate::auth::authenticate`], and
    /// the `bffEnabled` flag `GET /api/v1/auth/config` publishes.
    ///
    /// Call it **after** [`Self::with_auth_config`]: this sets `bffEnabled` on that value, so calling
    /// it first would let the later `with_auth_config` publish `bffEnabled: false` for a server that
    /// really answers the cookie flow.
    #[must_use]
    pub fn with_bff(mut self, bff: Arc<crate::auth_bff::BffState>) -> Self {
        self.auth_config.bff_enabled = true;
        self.bff = Some(bff);
        self
    }

    /// Whether `GET /api/v1/auth/config` can publish an honest answer for the selected policy.
    ///
    /// `true` for every policy that does not require OIDC, and — for [`AuthPolicy::Oidc`] and
    /// [`AuthPolicy::TokenReviewOrOidc`] — only once [`Self::with_auth_config`] supplied both the
    /// issuer and the client id (`PublicAuthConfig::oidc`). Finding `N4a`: an embedder cannot
    /// publish `authMode: "oidc"` with no issuer and no client id without this returning `false`,
    /// which the discovery handler `debug_assert!`s.
    #[must_use]
    pub fn auth_config_matches_policy(&self) -> bool {
        !self.auth.requires_oidc()
            || (self.auth_config.issuer.is_some() && self.auth_config.client_id.is_some())
    }

    /// Replaces the project-scoped authorization policy (`T14.4`).
    #[must_use]
    pub fn with_rbac(mut self, rbac: Arc<RbacPolicy>) -> Self {
        self.rbac = RbacPolicyStore::from_arc(rbac);
        self
    }

    /// Replaces the live-reloading project-scoped authorization policy store (`T17.1`).
    #[must_use]
    pub fn with_rbac_store(mut self, rbac: RbacPolicyStore) -> Self {
        self.rbac = rbac;
        self
    }

    /// Sets the control-plane namespace used by the empty-RBAC startup warning (`T17.1`).
    #[must_use]
    pub fn with_rbac_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.rbac_namespace = namespace.into();
        self
    }

    /// Replaces the readiness probe.
    #[must_use]
    pub fn with_readiness(mut self, readiness: Arc<dyn Readiness>) -> Self {
        self.readiness = readiness;
        self
    }

    /// Replaces the compliance audit logger (`T17.2`).
    #[must_use]
    pub fn with_audit(mut self, audit: AuditLogger) -> Self {
        self.audit = audit;
        self
    }

    /// Replaces the Kubernetes `Event` reader (`T17.3`).
    #[must_use]
    pub fn with_event_source(mut self, events: Arc<dyn EventSource>) -> Self {
        self.events = events;
        self
    }

    /// Replaces the SSE snapshot feed (`T17.3`).
    #[must_use]
    pub fn with_snapshot_source(mut self, snapshots: Arc<dyn ApplicationSnapshotSource>) -> Self {
        self.snapshots = snapshots;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operation_payloads_are_the_documented_ones() {
        assert_eq!(OperationRequest::Sync.annotation_value(), r#"{"sync":{}}"#);
        assert_eq!(
            OperationRequest::Rollback { id: 7 }.annotation_value(),
            r#"{"rollback":{"id":7}}"#
        );
        assert_eq!(OperationRequest::Sync.label(), "sync");
        assert_eq!(OperationRequest::Rollback { id: 1 }.label(), "rollback");
    }

    /// The sync payload must not look like a rollback to the controller's parser, and the rollback
    /// payload must parse as one: the API and the controller share one contract.
    #[test]
    fn the_payloads_parse_exactly_as_the_controller_expects() {
        assert!(
            matches!(
                ferriscd_engine::sync::parse_rollback_request(
                    &OperationRequest::Sync.annotation_value()
                ),
                Err(ferriscd_engine::sync::RollbackError::NotARollback)
            ),
            "a manual sync is not a rollback"
        );
        let request = ferriscd_engine::sync::parse_rollback_request(
            &OperationRequest::Rollback { id: 4 }.annotation_value(),
        )
        .expect("a rollback payload must parse");
        assert_eq!(request.id, 4);
    }

    #[test]
    fn a_rollback_id_is_never_reformatted_into_something_else() {
        for id in [0_i64, 1, 19, i64::MAX] {
            let value = OperationRequest::Rollback { id }.annotation_value();
            let parsed = ferriscd_engine::sync::parse_rollback_request(&value)
                .expect("every history id the API writes must parse back");
            assert_eq!(parsed.id, id);
        }
    }

    /// **Finding `P14-H2`:** the cache is per `(cluster, namespace, kind)` and it really prevents the
    /// read — a hit must not call the lister at all (a hit that re-listed would prove nothing).
    #[tokio::test]
    async fn a_listing_is_issued_once_per_cluster_namespace_and_kind() {
        let traversal = GraphTraversal::new();
        let key = ListKey::new("in-cluster", "payments", "ReplicaSet");

        let first = traversal
            .listing(key.clone(), || async {
                Ok(vec![ListedNode::new(
                    "api-abc",
                    vec![("Deployment".to_owned(), "api".to_owned())],
                )])
            })
            .await
            .expect("the first listing")
            .expect("inside the budget");
        assert_eq!(traversal.listings_issued(), 1);
        assert_eq!(first[0].name, "api-abc");
        assert!(first[0].owned_by("Deployment", "api"));
        assert!(!first[0].owned_by("Deployment", "worker"));

        // The same key again: served from the cache, so the lister is never called (it would panic).
        let second = traversal
            .listing(key, || async {
                panic!("a cached listing must not re-read the cluster");
            })
            .await
            .expect("the cached listing")
            .expect("and it is inside the budget");
        assert_eq!(second[0].name, "api-abc");
        assert_eq!(traversal.listings_issued(), 1);

        // A different namespace (or cluster, or kind) is a different read.
        for key in [
            ListKey::new("in-cluster", "other", "ReplicaSet"),
            ListKey::new("eu-prod", "payments", "ReplicaSet"),
            ListKey::new("in-cluster", "payments", "Pod"),
        ] {
            traversal
                .listing(key, || async { Ok(Vec::new()) })
                .await
                .expect("a listing")
                .expect("inside the budget");
        }
        assert_eq!(traversal.listings_issued(), 4);
        assert!(!traversal.is_exhausted());
    }

    /// The request-wide budget is a hard ceiling: once it is spent every further listing answers
    /// `None` and the request reports itself truncated.
    #[tokio::test]
    async fn the_listing_budget_is_enforced() {
        let traversal = GraphTraversal::new();
        for index in 0..MAX_GRAPH_LIST_REQUESTS {
            let key = ListKey::new("in-cluster", &format!("namespace-{index}"), "Pod");
            assert!(
                traversal
                    .listing(key, || async { Ok(Vec::new()) })
                    .await
                    .expect("a listing")
                    .is_some(),
                "listing {index} is inside the budget"
            );
        }
        assert_eq!(traversal.listings_issued(), MAX_GRAPH_LIST_REQUESTS);
        assert!(!traversal.is_exhausted());

        let over = traversal
            .listing(ListKey::new("in-cluster", "one-more", "Pod"), || async {
                panic!("a spent budget must not reach the cluster");
            })
            .await
            .expect("an exhausted traversal is not an error");
        assert!(over.is_none(), "no listing, no children, no error");
        assert!(traversal.is_exhausted(), "and the response says so");
        assert_eq!(
            traversal.listings_issued(),
            MAX_GRAPH_LIST_REQUESTS,
            "a refused listing is not charged"
        );
    }
}
