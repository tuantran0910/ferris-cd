//! Production wiring: one thin adapter per [`crate::state`] seam.
//!
//! Everything here is built from the [`ControlPlane`] the binary already constructed, so the API
//! shares the controller's `kube::Client`, connector pool, `ClusterManager`, `DiscoveryCache`,
//! `RepoCache` and renderer cache. There is no second client, no second cache, and no background
//! informer: `GET .../resources` performs one scoped read per inventory key, plus **one**
//! namespace-scoped `ReplicaSet`/`Pod` list per `(cluster, namespace)` for the whole request
//! (finding `P14-H2`; `ADR-004`).
//!
//! The adapters are intentionally dumb: they translate a seam call into one `kube` call and map
//! failures onto [`ApiError`]. All policy, rendering, diffing and redaction stay in the engine and
//! the controller — duplicating any of it here is exactly the flaw finding C9 removed.

use std::sync::Arc;

use ferriscd_controller::{
    ClusterManager, ControlPlane, ControlPlaneReadiness, DiffPreview, Metrics, RbacReloadOutcome,
    TrackingOwner,
};
use ferriscd_crd::annotations;
use ferriscd_crd::{AppProject, Application};
use ferriscd_engine::inventory::{self, Inventory};
use ferriscd_engine::manifest::ResourceKey;
use futures::StreamExt as _;
use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::api::authentication::v1::{TokenReview, TokenReviewSpec};
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::WatchStreamExt as _;
use kube::runtime::watcher::{self, Event as WatcherEvent};
use kube::{Client, ResourceExt};
use tokio_util::sync::CancellationToken;

use crate::auth::{
    AuthPolicy, AuthenticatedIdentity, IdentityCache, MAX_BEARER_TOKEN_CHARS, TokenAuthenticator,
};
use crate::error::ApiError;
use crate::rbac::{
    RBAC_CONFIGMAP_KEY, RBAC_CONFIGMAP_NAME, RbacConfigMapEvent, RbacPolicy, RbacPolicyError,
    RbacPolicyStore,
};
use crate::state::{
    AppState, ApplicationSource, ChildNode, ClusterCatalog, ClusterEntry, DiffSource,
    GRAPH_LIST_LIMIT, GraphRequest, GraphTraversal, InventoryReader, ListKey, ListedNode,
    LiveResourceState, OperationRequest, OperationWriter, ProjectCatalog, Readiness, SeamFuture,
    WorkloadGraphSource,
};
use crate::webhooks::{RefreshSink, RefreshTarget, WebhookConfig};

/// Adapter connecting [`ControlPlaneReadiness`] (`ferriscd-controller`) to [`Readiness`] (`GET /readyz`, `T17.1`).
///
/// Allocates zero heap memory on the steady-state ready path.
#[derive(Debug, Clone)]
pub struct KubeControlPlaneReadiness {
    inner: ControlPlaneReadiness,
}

impl KubeControlPlaneReadiness {
    /// Wraps the control plane's startup readiness barrier.
    #[must_use]
    pub fn new(inner: ControlPlaneReadiness) -> Self {
        Self { inner }
    }
}

impl Readiness for KubeControlPlaneReadiness {
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }

    fn reason(&self) -> Option<String> {
        self.inner.reason()
    }
}

/// Builds the whole [`AppState`] from the shared control plane.
///
/// This is the **only** place the API meets the cluster, and every collaborator it takes is one the
/// controller is already using.
#[must_use]
pub fn app_state(plane: &ControlPlane, webhooks: WebhookConfig) -> AppState {
    let client = plane.client().clone();
    let clusters = plane.clusters();
    let refreshes: Arc<dyn RefreshSink> = Arc::new(ApiRefreshSink::new(client.clone()));
    AppState::new(
        Arc::new(KubeApplicationSource::new(
            client.clone(),
            plane.application_scope(),
        )),
        Arc::new(KubeProjectCatalog::new(client.clone(), plane.namespace())),
        Arc::new(RegistryClusterCatalog::new(clusters.clone())),
        Arc::new(KubeOperationWriter::new(client.clone())),
        Arc::new(KubeInventoryReader::new(clusters.clone())),
        Arc::new(KubeWorkloadGraphSource::new(clusters)),
        Arc::new(PipelineDiff::new(plane.sync_pipeline())),
        Arc::new(KubeControlPlaneReadiness::new(plane.readiness())),
    )
    .with_refresh_sink(refreshes)
    // `T14.3`: the production bearer-token validator. `AppState` defaults to a validator that
    // refuses everything, so forgetting this line fails closed rather than open.
    .with_token_authenticator(Arc::new(KubeTokenAuthenticator::new(
        plane.client().clone(),
    )))
    .with_identity_cache(Arc::new(IdentityCache::default()))
    // `T14.4` / `T17.1`: deny everything until `load_rbac_policy` / `watch_rbac_policy` loads
    // `ferriscd-rbac-cm`.
    .with_rbac_store(RbacPolicyStore::empty())
    .with_webhooks(webhooks)
}

/// Reads `Application`s the control plane is allowed to own.
///
/// The namespace selection is the controller's own [`ApplicationScope`](ferriscd_engine::policy::ApplicationScope):
/// with the default (control-plane namespace only) a tenant `Application` written into another
/// namespace is **invisible** here, which is what keeps the API from reporting objects the
/// controller would refuse to reconcile (`T12.2`).
pub struct KubeApplicationSource {
    client: Client,
    scope: ferriscd_engine::policy::ApplicationScope,
}

impl std::fmt::Debug for KubeApplicationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeApplicationSource")
            .field("scope", &self.scope.describe())
            .finish_non_exhaustive()
    }
}

impl KubeApplicationSource {
    /// Builds a source over `scope`.
    #[must_use]
    pub fn new(client: Client, scope: ferriscd_engine::policy::ApplicationScope) -> Self {
        Self { client, scope }
    }
}

impl ApplicationSource for KubeApplicationSource {
    fn list(&self) -> SeamFuture<'_, Vec<Application>> {
        Box::pin(async move {
            let mut items = Vec::new();
            match self.scope.watch_namespaces() {
                // Apps-in-any-namespace (`T12.2`): a cluster-wide list is the only correct answer.
                None => {
                    let api: Api<Application> = Api::all(self.client.clone());
                    items = api
                        .list(&ListParams::default())
                        .await
                        .map_err(|err| ApiError::backend(&err))?
                        .items;
                }
                Some(namespaces) => {
                    for namespace in namespaces {
                        let api: Api<Application> =
                            Api::namespaced(self.client.clone(), &namespace);
                        let mut listed = api
                            .list(&ListParams::default())
                            .await
                            .map_err(|err| ApiError::backend(&err))?
                            .items;
                        items.append(&mut listed);
                    }
                }
            }
            items.sort_by_key(|app| (app.namespace().unwrap_or_default(), app.name_any()));
            Ok(items)
        })
    }

    fn get(&self, namespace: &str, name: &str) -> SeamFuture<'_, Option<Application>> {
        // A namespace the controller does not watch answers "not found", never "forbidden": the API
        // must not become a way to discover `Application`s the control plane does not own.
        if !self.scope.allows(namespace) {
            return Box::pin(async { Ok(None) });
        }
        let api: Api<Application> = Api::namespaced(self.client.clone(), namespace);
        let name = name.to_owned();
        Box::pin(async move {
            api.get_opt(&name)
                .await
                .map_err(|err| ApiError::backend(&err))
        })
    }
}

/// Reads `AppProject`s from the control-plane namespace (never cluster-wide).
pub struct KubeProjectCatalog {
    api: Api<AppProject>,
}

impl std::fmt::Debug for KubeProjectCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeProjectCatalog").finish_non_exhaustive()
    }
}

impl KubeProjectCatalog {
    /// Builds a catalog reading `namespace` (the control-plane namespace).
    #[must_use]
    pub fn new(client: Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
        }
    }
}

impl ProjectCatalog for KubeProjectCatalog {
    fn list(&self) -> SeamFuture<'_, Vec<AppProject>> {
        Box::pin(async move {
            let mut items = self
                .api
                .list(&ListParams::default())
                .await
                .map_err(|err| ApiError::backend(&err))?
                .items;
            items.sort_by_key(|project| project.name_any());
            Ok(items)
        })
    }
}

/// Lists the cluster registry (`T13.1`): `in-cluster` first, then every registration.
pub struct RegistryClusterCatalog {
    clusters: Arc<ClusterManager>,
}

impl std::fmt::Debug for RegistryClusterCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryClusterCatalog")
            .field("clusters", &self.clusters.names())
            .finish_non_exhaustive()
    }
}

impl RegistryClusterCatalog {
    /// Wraps the shared registry.
    #[must_use]
    pub fn new(clusters: Arc<ClusterManager>) -> Self {
        Self { clusters }
    }
}

impl ClusterCatalog for RegistryClusterCatalog {
    fn list(&self) -> Vec<ClusterEntry> {
        let mut entries = vec![ClusterEntry {
            name: ferriscd_controller::cluster_manager::IN_CLUSTER.to_owned(),
            in_cluster: true,
        }];
        entries.extend(self.clusters.names().into_iter().map(|name| ClusterEntry {
            name,
            in_cluster: false,
        }));
        entries
    }
}

/// Patches `ferriscd.io/operation` with a resource-version precondition.
pub struct KubeOperationWriter {
    client: Client,
}

impl std::fmt::Debug for KubeOperationWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeOperationWriter")
            .finish_non_exhaustive()
    }
}

impl KubeOperationWriter {
    /// Builds a writer over `client`.
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl OperationWriter for KubeOperationWriter {
    fn request<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
        resource_version: Option<&'a str>,
        operation: OperationRequest,
    ) -> SeamFuture<'a, ()> {
        let api: Api<Application> = Api::namespaced(self.client.clone(), namespace);
        let name = name.to_owned();
        let resource_version = resource_version.map(ToOwned::to_owned);
        Box::pin(async move {
            // The `resourceVersion` in the body is the compare-and-swap precondition (`kube 5.1`'s
            // `PatchParams` has no field for it): if the object changed between the read that
            // decided the operation was allowed and this write, the API server refuses the merge
            // patch with `409 Conflict` instead of overwriting somebody else's request.
            let mut metadata = serde_json::json!({
                "annotations": { annotations::OPERATION: operation.annotation_value() }
            });
            if let Some(version) = resource_version {
                metadata["resourceVersion"] = serde_json::Value::String(version);
            }
            let patch = serde_json::json!({ "metadata": metadata });
            match api
                .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
            {
                Ok(_) => Ok(()),
                Err(kube::Error::Api(status)) if status.code == 409 => Err(ApiError::conflict(
                    "the Application changed while the operation was being recorded; retry",
                )),
                Err(kube::Error::Api(status)) if status.code == 404 => {
                    Err(ApiError::not_found("Application", namespace, &name))
                }
                Err(err) => Err(ApiError::backend(&err)),
            }
        })
    }
}

/// Reads the live state of `status.inventory` through the shared `ClusterStateReader`.
///
/// The read is exactly a reconcile's live read — same discovery cache, same ownership
/// classification (`ferriscd.io/tracking-id`), same bounded concurrency — minus the desired set,
/// because a graph endpoint has no desired set to compare against.
pub struct KubeInventoryReader {
    clusters: Arc<ClusterManager>,
}

impl std::fmt::Debug for KubeInventoryReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeInventoryReader")
            .finish_non_exhaustive()
    }
}

impl KubeInventoryReader {
    /// Wraps the shared registry.
    #[must_use]
    pub fn new(clusters: Arc<ClusterManager>) -> Self {
        Self { clusters }
    }
}

impl InventoryReader for KubeInventoryReader {
    fn read<'a>(&'a self, app: &'a Application) -> SeamFuture<'a, Vec<LiveResourceState>> {
        Box::pin(async move {
            let entries: &[ferriscd_crd::status::InventoryEntry] = app
                .status
                .as_ref()
                .map_or(&[][..], |status| status.inventory.as_slice());
            if entries.is_empty() {
                return Ok(Vec::new());
            }
            let owner = TrackingOwner::for_application(app).ok_or_else(|| {
                ApiError::unprocessable(
                    "the Application has no metadata.namespace, so its resources cannot be verified",
                )
            })?;
            let inventory =
                inventory::from_status_entries(entries).map_err(|err| ApiError::backend(&err))?;
            let handle = self
                .clusters
                .get(&app.spec.destination.cluster)
                .map_err(|err| ApiError::backend(&err))?;
            let target = handle.target();
            // No desired set: every request is an inventory key, so `plan_fetch` is the identity.
            let requests =
                ferriscd_controller::live_state::plan_fetch(&Inventory::new(), &inventory);
            let live = target
                .access()
                .reader()
                .fetch_live(&requests, target.discovery(), &[], &[], &owner)
                .await
                .map_err(|err| ApiError::backend(&err))?;
            Ok(live
                .into_iter()
                .map(|(key, state)| LiveResourceState {
                    ownership: state.ownership().map(ownership_label),
                    present: state.is_present(),
                    key,
                })
                .collect())
        })
    }
}

/// A stable, non-secret ownership label.
fn ownership_label(ownership: &ferriscd_engine::inventory::Ownership) -> &'static str {
    match ownership {
        ferriscd_engine::inventory::Ownership::OwnedBySelf => "OwnedBySelf",
        ferriscd_engine::inventory::Ownership::Unmanaged => "Unmanaged",
        ferriscd_engine::inventory::Ownership::OwnedByForeign(_) => "OwnedByForeign",
    }
}

/// Reads one namespace's `ReplicaSet`s or `Pod`s for the graph traversal.
///
/// This is the graph's **only** cluster read, split out so the traversal can cache it per
/// `(cluster, namespace, kind)` and so a test can count the reads without a cluster.
pub trait WorkloadNodeLister: Send + Sync + 'static {
    /// Lists every `ReplicaSet`/`Pod` in `namespace` of `cluster`, reduced to its owner references.
    fn list(
        &self,
        cluster: &str,
        namespace: &str,
        kind: GraphListKind,
    ) -> SeamFuture<'_, Vec<ListedNode>>;
}

/// The kinds the graph traversal lists (never anything else: a `ConfigMap` owns no pods).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphListKind {
    /// `apps/v1` `ReplicaSet`s (children of a `Deployment`/`StatefulSet`/`DaemonSet`).
    ReplicaSet,
    /// core `Pod`s (children of a `ReplicaSet`).
    Pod,
}

impl GraphListKind {
    /// The label used in the per-request cache key and in logs.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ReplicaSet => "ReplicaSet",
            Self::Pod => "Pod",
        }
    }

    /// The listing parameters: **bounded**, so one huge namespace cannot make one HTTP request
    /// allocate an unbounded node list (finding `P14-H2`).
    #[must_use]
    pub fn params(self) -> ListParams {
        ListParams::default().limit(GRAPH_LIST_LIMIT)
    }
}

/// The production lister: the shared `ClusterManager`'s client for the destination cluster.
pub struct KubeNodeLister {
    clusters: Arc<ClusterManager>,
}

impl std::fmt::Debug for KubeNodeLister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeNodeLister").finish_non_exhaustive()
    }
}

impl KubeNodeLister {
    /// Wraps the shared registry.
    #[must_use]
    pub fn new(clusters: Arc<ClusterManager>) -> Self {
        Self { clusters }
    }
}

impl WorkloadNodeLister for KubeNodeLister {
    fn list(
        &self,
        cluster: &str,
        namespace: &str,
        kind: GraphListKind,
    ) -> SeamFuture<'_, Vec<ListedNode>> {
        let cluster = cluster.to_owned();
        let namespace = namespace.to_owned();
        Box::pin(async move {
            let handle = self
                .clusters
                .get(&cluster)
                .map_err(|err| ApiError::backend(&err))?;
            let client = handle.client().clone();
            match kind {
                GraphListKind::ReplicaSet => {
                    let api: Api<ReplicaSet> = Api::namespaced(client, &namespace);
                    let listed = api
                        .list(&kind.params())
                        .await
                        .map_err(|err| ApiError::backend(&err))?;
                    Ok(listed
                        .items
                        .into_iter()
                        .map(|replica_set| {
                            ListedNode::new(replica_set.name_any(), owner_pairs(&replica_set))
                        })
                        .collect())
                }
                GraphListKind::Pod => {
                    let api: Api<Pod> = Api::namespaced(client, &namespace);
                    let listed = api
                        .list(&kind.params())
                        .await
                        .map_err(|err| ApiError::backend(&err))?;
                    Ok(listed
                        .items
                        .into_iter()
                        .map(|pod| ListedNode::new(pod.name_any(), owner_pairs(&pod)))
                        .collect())
                }
            }
        })
    }
}

/// Discovers `Deployment -> ReplicaSet -> Pod` children by `metadata.ownerReferences`.
///
/// The traversal lists each `(cluster, namespace, kind)` **once per request** through
/// [`GraphTraversal`] and matches owner references in memory, so a bundle with twenty
/// `Deployment`s costs one `ReplicaSet` list (plus one `Pod` list per `ReplicaSet`) instead of one
/// listing per workload (finding `P14-H2`). Each listing is `limit`ed ([`GRAPH_LIST_LIMIT`]) and the
/// request may issue at most [`MAX_GRAPH_LIST_REQUESTS`](crate::state::MAX_GRAPH_LIST_REQUESTS) of
/// them, so `/resources` is never an unbounded, sequential cluster walk.
pub struct KubeWorkloadGraphSource {
    lister: Arc<dyn WorkloadNodeLister>,
}

impl std::fmt::Debug for KubeWorkloadGraphSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeWorkloadGraphSource")
            .finish_non_exhaustive()
    }
}

impl KubeWorkloadGraphSource {
    /// Wraps the shared registry.
    #[must_use]
    pub fn new(clusters: Arc<ClusterManager>) -> Self {
        Self::with_lister(Arc::new(KubeNodeLister::new(clusters)))
    }

    /// Builds a graph source over an explicit lister (the seam the tests substitute).
    #[must_use]
    pub fn with_lister(lister: Arc<dyn WorkloadNodeLister>) -> Self {
        Self { lister }
    }
}

impl WorkloadGraphSource for KubeWorkloadGraphSource {
    fn children<'a>(
        &'a self,
        traversal: &'a GraphTraversal,
        parent: &GraphRequest<'_>,
    ) -> SeamFuture<'a, Vec<ChildNode>> {
        let cluster = parent.cluster.to_owned();
        let namespace = parent.namespace.to_owned();
        let kind = parent.kind.to_owned();
        let name = parent.name.to_owned();
        Box::pin(async move {
            // Nothing else owns pods; answering "no children" is the honest result.
            let Some(list_kind) = list_kind_for(&kind) else {
                return Ok(Vec::new());
            };
            let key = ListKey::new(&cluster, &namespace, list_kind.label());
            let Some(listed) = traversal
                .listing(key, || self.lister.list(&cluster, &namespace, list_kind))
                .await?
            else {
                // The request's listing budget is spent: no children, and the handler reports the
                // graph as truncated.
                return Ok(Vec::new());
            };
            Ok(listed
                .iter()
                .filter(|node| node.owned_by(&kind, &name))
                .map(|node| ChildNode {
                    key: ResourceKey::new(
                        child_group(list_kind),
                        list_kind.label(),
                        Some(namespace.clone()),
                        node.name.clone(),
                    ),
                    cluster: cluster.clone(),
                })
                .collect())
        })
    }
}

/// The kind of listing that has to be read to find `kind`'s children.
fn list_kind_for(kind: &str) -> Option<GraphListKind> {
    match kind {
        "Deployment" | "StatefulSet" | "DaemonSet" => Some(GraphListKind::ReplicaSet),
        "ReplicaSet" => Some(GraphListKind::Pod),
        _ => None,
    }
}

/// The API group of a listed child kind.
const fn child_group(kind: GraphListKind) -> &'static str {
    match kind {
        GraphListKind::ReplicaSet => "apps",
        GraphListKind::Pod => "",
    }
}

/// The `(kind, name)` pairs of an object's `metadata.ownerReferences`.
fn owner_pairs<K: ResourceExt>(object: &K) -> Vec<(String, String)> {
    object
        .meta()
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|reference| (reference.kind.clone(), reference.name.clone()))
        .collect()
}

/// The controller's own pipeline, as the API's [`DiffSource`] (`T14.1`, finding C9).
pub struct PipelineDiff {
    pipeline: Arc<dyn ferriscd_controller::SyncPipeline>,
}

impl std::fmt::Debug for PipelineDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PipelineDiff").finish_non_exhaustive()
    }
}

impl PipelineDiff {
    /// Wraps the shared pipeline.
    #[must_use]
    pub fn new(pipeline: Arc<dyn ferriscd_controller::SyncPipeline>) -> Self {
        Self { pipeline }
    }
}

impl DiffSource for PipelineDiff {
    fn diff<'a>(&'a self, app: &'a Application) -> SeamFuture<'a, DiffPreview> {
        Box::pin(async move {
            self.pipeline
                .diff(app)
                .await
                .map_err(|err| ApiError::backend(&err))
        })
    }
}

/// Writes `ferriscd.io/refresh` so the composite watch predicate schedules a reconcile.
pub struct ApiRefreshSink {
    client: Client,
}

impl std::fmt::Debug for ApiRefreshSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiRefreshSink").finish_non_exhaustive()
    }
}

impl ApiRefreshSink {
    /// Builds a sink over `client`.
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl RefreshSink for ApiRefreshSink {
    fn refresh(&self, target: RefreshTarget) -> SeamFuture<'_, ()> {
        let api: Api<Application> = Api::namespaced(self.client.clone(), &target.namespace);
        Box::pin(async move {
            // The value must change on every refresh: an identical annotation leaves the composite
            // predicate's hash unchanged and the watch would swallow the request entirely.
            let patch = serde_json::json!({
                "metadata": {
                    "annotations": {
                        annotations::REFRESH: crate::webhooks::refresh_token(),
                    }
                }
            });
            api.patch(&target.name, &PatchParams::default(), &Patch::Merge(&patch))
                .await
                .map(|_| ())
                .map_err(|err| ApiError::backend(&err))
        })
    }
}

/// The production [`TokenAuthenticator`]: one `authentication.k8s.io/v1` `TokenReview` per token.
///
/// # Why a `TokenReview` and not a JWT check
///
/// FerrisCD never issues or introspects credentials itself: Kubernetes is the identity provider for
/// every workload in the cluster, and a `TokenReview` is the only way to ask *it* whether a token is
/// currently valid — including audience binding, expiry and a `ServiceAccount` that has been
/// deleted. Verifying a JWT locally would require the cluster's signing key and would keep accepting
/// a revoked identity until the token expired.
///
/// # Cost
///
/// A `TokenReview` is a create against the API server (an etcd write). This type is therefore always
/// behind [`IdentityCache`](crate::auth::IdentityCache), which turns a polling dashboard's requests
/// into one review per identity per 30 s.
///
/// # RBAC
///
/// The control plane's `ServiceAccount` needs `create` on
/// `tokenreviews.authentication.k8s.io`; without it every review fails and every protected request
/// answers `401` (fail closed). The lesson documents the `ClusterRole`.
pub struct KubeTokenAuthenticator {
    client: Client,
}

impl std::fmt::Debug for KubeTokenAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KubeTokenAuthenticator")
            .finish_non_exhaustive()
    }
}

impl KubeTokenAuthenticator {
    /// Builds the validator over the controller's own client (no second connector pool).
    #[must_use]
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

impl TokenAuthenticator for KubeTokenAuthenticator {
    fn authenticate<'a>(&'a self, token: &'a str) -> SeamFuture<'a, Option<AuthenticatedIdentity>> {
        Box::pin(async move {
            // Defence in depth: the middleware already refused an over-long credential, and this
            // guard keeps the request body bounded even if a future caller forgets.
            if token.is_empty() || token.chars().count() > MAX_BEARER_TOKEN_CHARS {
                return Ok(None);
            }
            let review = TokenReview {
                spec: TokenReviewSpec {
                    token: Some(token.to_owned()),
                    audiences: None,
                },
                ..TokenReview::default()
            };
            // `TokenReview` is cluster-scoped: `Api::all`, never a namespace.
            let api: Api<TokenReview> = Api::all(self.client.clone());
            let reviewed = api
                .create(&PostParams::default(), &review)
                .await
                .map_err(|err| ApiError::backend(&err))?;
            let status = reviewed.status.unwrap_or_default();
            if status.authenticated != Some(true) {
                return Ok(None);
            }
            let Some(user) = status.user else {
                // `authenticated: true` without a user is not an identity anybody can be authorized
                // against, so it is refused rather than half-trusted.
                return Ok(None);
            };
            let Some(username) = user.username else {
                // `authenticated: true` with no user name is not an identity that can be authorized.
                return Ok(None);
            };
            if username.trim().is_empty() {
                return Ok(None);
            }
            Ok(Some(AuthenticatedIdentity::new(
                username,
                user.groups.unwrap_or_default(),
            )))
        })
    }
}

/// Why the RBAC `ConfigMap` could not be turned into a policy.
///
/// Every variant means **deny everything** (`T14.4`: the policy fails closed). None of them quotes
/// a value from the document: the loader's job is to log *which* ConfigMap is broken, not to
/// publish the group names inside it.
#[derive(Debug, thiserror::Error)]
pub enum RbacLoadError {
    /// There is no `ferriscd-rbac-cm` in the control-plane namespace.
    #[error(
        "the RBAC ConfigMap {namespace}/{name} does not exist, so no authenticated caller is \
         authorized for anything"
    )]
    Missing {
        /// Namespace that was searched.
        namespace: String,
        /// ConfigMap name that is required.
        name: String,
    },

    /// The `ConfigMap` exists but has no `policy.yaml` entry.
    #[error(
        "the RBAC ConfigMap {namespace}/{name} has no `{key}` entry, so no authenticated caller is \
         authorized for anything"
    )]
    MissingKey {
        /// Namespace the ConfigMap lives in.
        namespace: String,
        /// ConfigMap name.
        name: String,
        /// The key that was expected.
        key: String,
    },

    /// The `ConfigMap` could not be read from the cluster.
    #[error("the RBAC ConfigMap {namespace}/{name} could not be read: {source}")]
    Read {
        /// Namespace the ConfigMap lives in.
        namespace: String,
        /// ConfigMap name.
        name: String,
        /// The API failure.
        #[source]
        source: kube::Error,
    },

    /// The document is not a valid policy.
    #[error("the RBAC ConfigMap {namespace}/{name} is not a usable policy: {source}")]
    Invalid {
        /// Namespace the ConfigMap lives in.
        namespace: String,
        /// ConfigMap name.
        name: String,
        /// Why the document was rejected.
        #[source]
        source: RbacPolicyError,
    },
}

/// Reads [`RBAC_CONFIGMAP_NAME`] from the control-plane namespace and turns it into a policy.
///
/// Deliberately **not** a per-request load: an `Application` list or a diff already costs cluster
/// reads, and an authorization decision that costs an etcd read per request would be a fine denial
/// of service against the API server. The initial snapshot is loaded at startup (`T14.4`), and
/// [`watch_rbac_policy`] keeps the active [`RbacPolicyStore`] hot-reloaded without restarts (`T17.1`).
#[derive(Debug, Clone)]
pub struct KubeRbacLoader {
    api: Api<ConfigMap>,
    namespace: String,
}

impl KubeRbacLoader {
    /// Builds a loader reading `namespace` (the control-plane namespace).
    #[must_use]
    pub fn new(client: Client, namespace: impl Into<String>) -> Self {
        let namespace = namespace.into();
        Self {
            api: Api::namespaced(client, &namespace),
            namespace,
        }
    }

    /// The namespace the policy is read from.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Reads and parses the policy.
    ///
    /// # Errors
    ///
    /// [`RbacLoadError`] when the ConfigMap is missing, unreadable, missing its `policy.yaml` entry,
    /// or not a valid policy document.
    pub async fn load(&self) -> Result<RbacPolicy, RbacLoadError> {
        let config_map =
            self.api
                .get_opt(RBAC_CONFIGMAP_NAME)
                .await
                .map_err(|err| RbacLoadError::Read {
                    namespace: self.namespace.clone(),
                    name: RBAC_CONFIGMAP_NAME.to_owned(),
                    source: err,
                })?;
        let Some(config_map) = config_map else {
            return Err(RbacLoadError::Missing {
                namespace: self.namespace.clone(),
                name: RBAC_CONFIGMAP_NAME.to_owned(),
            });
        };
        let document = config_map
            .data
            .as_ref()
            .and_then(|data| data.get(RBAC_CONFIGMAP_KEY))
            .ok_or_else(|| RbacLoadError::MissingKey {
                namespace: self.namespace.clone(),
                name: RBAC_CONFIGMAP_NAME.to_owned(),
                key: RBAC_CONFIGMAP_KEY.to_owned(),
            })?;
        RbacPolicy::parse(document).map_err(|source| RbacLoadError::Invalid {
            namespace: self.namespace.clone(),
            name: RBAC_CONFIGMAP_NAME.to_owned(),
            source,
        })
    }
}

/// Loads the RBAC policy for the binary, falling back to deny-all with a loud log.
///
/// The fallback is the whole point (`T14.4` trap guard): a missing, unreadable or malformed policy
/// must make the API authorize **nobody**, never everybody. The server keeps serving (probes and
/// webhooks are unaffected, and an operator can fix the ConfigMap and restart) instead of crashing
/// into a crash loop that hides the actual problem.
pub async fn load_rbac_policy(plane: &ControlPlane) -> RbacPolicy {
    load_initial_rbac_policy(plane).await.0
}

/// Loads the initial RBAC policy and reports whether the Kubernetes API call itself succeeded.
///
/// Returns `(policy, api_reachable)`:
/// - `Ok(_)`, `Err(Missing)`, `Err(MissingKey)`, and `Err(Invalid)` all represent an authoritative
///   answer from the API server (`api_reachable = true`), so `/readyz` can mark the RBAC gate
///   complete (failing closed to deny-all on missing/malformed policy).
/// - `Err(RbacLoadError::Read { .. })` means the API server could not be read (`api_reachable =
///   false`), so `/readyz` stays `503` until [`watch_rbac_policy`]'s first `InitDone` completes.
pub async fn load_initial_rbac_policy(plane: &ControlPlane) -> (RbacPolicy, bool) {
    let loader = KubeRbacLoader::new(plane.client().clone(), plane.namespace());
    let result = loader.load().await;
    let api_reachable = !matches!(result, Err(RbacLoadError::Read { .. }));
    if result.is_ok() {
        tracing::info!(
            configmap = %format!("{}/{}", loader.namespace(), RBAC_CONFIGMAP_NAME),
            rules = result.as_ref().map_or(0, RbacPolicy::rule_count),
            "loaded the project-scoped RBAC policy"
        );
    }
    (fallback_to_deny_all(result), api_reachable)
}

/// The binary's fail-closed fallback: a load error becomes an **empty** policy.
///
/// Split out from [`load_rbac_policy`] so the decision — the one thing that must never regress to
/// "allow everybody" — is a pure function a test can drive without a cluster.
#[must_use]
pub fn fallback_to_deny_all(result: Result<RbacPolicy, RbacLoadError>) -> RbacPolicy {
    match result {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(
                error = %error,
                "the RBAC policy could not be loaded; every authenticated request will be refused \
                 (fail closed). Publish or fix the `{}` ConfigMap (key `{}`) — changes reload \
                 automatically without restarting",
                RBAC_CONFIGMAP_NAME,
                RBAC_CONFIGMAP_KEY,
            );
            RbacPolicy::empty()
        }
    }
}

/// Whether `state` would refuse every authenticated caller (used by the startup warnings).
#[must_use]
pub fn denies_every_authenticated_caller(state: &AppState) -> bool {
    state.auth == AuthPolicy::TokenReview && state.rbac.is_empty()
}

/// Watches `ferriscd-rbac-cm` in `namespace` (**strictly namespaced**, never cluster-wide —
/// `T17.1` trap guard) and updates `store` live without restarting `ferriscd server`.
///
/// - Valid updates atomically swap the active [`RbacPolicy`] and increment
///   `ferriscd_rbac_reload_total{outcome="ok"}`.
/// - Malformed updates or missing `policy.yaml` keys **retain the last known-good policy** and
///   increment `ferriscd_rbac_reload_total{outcome="error"}`.
/// - Deleting `ferriscd-rbac-cm` (or omitting it from a completed watch re-list) transitions
///   immediately to [`RbacPolicy::empty`] (default-deny) and increments
///   `ferriscd_rbac_reload_total{outcome="deleted"}`.
/// - Marks `readiness.mark_rbac_loaded()` once the initial watch snapshot (`InitDone`) completes.
pub async fn watch_rbac_policy(
    client: Client,
    namespace: String,
    store: RbacPolicyStore,
    readiness: ControlPlaneReadiness,
    metrics: Metrics,
    stop: CancellationToken,
) {
    let api = rbac_configmap_api(client, &namespace);
    let config = watcher::Config::default().fields(&format!("metadata.name={RBAC_CONFIGMAP_NAME}"));
    let stream = watcher::watcher(api, config).default_backoff();
    drive_rbac_watch(stream, &namespace, store, readiness, metrics, stop).await;
}

/// Builds the **strictly namespaced** `ConfigMap` API used by the live RBAC watcher.
///
/// The control-plane namespace comes from `--namespace`; this must never be a cluster-wide `Api`
/// (`T17.1` Trap Guard).
fn rbac_configmap_api(client: Client, namespace: &str) -> Api<ConfigMap> {
    Api::namespaced(client, namespace)
}

/// Drives the live RBAC policy state machine over any Kubernetes `ConfigMap` watch stream.
///
/// Split out from [`watch_rbac_policy`] so every transition (`Init`/`InitApply`/`InitDone`,
/// re-list omission -> fail-closed `Deleted`, unchanged reconnect deduplication by
/// `resourceVersion`, live `Apply`/`Delete`, watch errors, and `InitDone` readiness) is unit-tested
/// deterministically without a cluster.
pub async fn drive_rbac_watch<S, E>(
    stream: S,
    namespace: &str,
    store: RbacPolicyStore,
    readiness: ControlPlaneReadiness,
    metrics: Metrics,
    stop: CancellationToken,
) where
    S: futures::Stream<Item = Result<WatcherEvent<ConfigMap>, E>>,
    E: std::fmt::Display,
{
    let mut stream = std::pin::pin!(stream);
    let mut seen_in_init = false;
    let mut listing = false;
    let mut initial_sync_done = false;
    let mut last_resource_version: Option<String> = None;

    loop {
        let next = tokio::select! {
            () = stop.cancelled() => break,
            event = stream.next() => event,
        };
        let Some(event) = next else {
            tracing::warn!(
                namespace = %namespace,
                configmap = RBAC_CONFIGMAP_NAME,
                "RBAC ConfigMap watch stream ended; active policy snapshot remains in effect"
            );
            metrics.record_rbac_watch_error();
            break;
        };
        match event {
            Ok(WatcherEvent::Init) => {
                seen_in_init = false;
                listing = true;
            }
            Ok(WatcherEvent::InitApply(cm)) => {
                if listing {
                    seen_in_init = true;
                }
                let rv = cm.metadata.resource_version.clone();
                if initial_sync_done && rv.is_some() && rv == last_resource_version {
                    // Routine watch reconnect / 410 re-list of the identical ConfigMap revision:
                    // skip re-parsing and do not inflate `ferriscd_rbac_reload_total`.
                    continue;
                }
                let doc = cm
                    .data
                    .as_ref()
                    .and_then(|data| data.get(RBAC_CONFIGMAP_KEY))
                    .cloned();
                let outcome = store.apply_event(RbacConfigMapEvent::Applied(doc));
                if outcome == RbacReloadOutcome::Ok {
                    last_resource_version = rv;
                }
                if initial_sync_done || outcome == RbacReloadOutcome::Error {
                    metrics.record_rbac_reload(outcome);
                }
            }
            Ok(WatcherEvent::InitDone) => {
                if std::mem::take(&mut listing) && !seen_in_init {
                    // The ConfigMap was absent from the complete list snapshot. If we had a policy
                    // loaded (e.g. ConfigMap deleted during a watch reconnect), fail closed now.
                    last_resource_version = None;
                    if !store.is_empty() {
                        let outcome = store.apply_event(RbacConfigMapEvent::Deleted);
                        metrics.record_rbac_reload(outcome);
                    }
                }
                initial_sync_done = true;
                readiness.mark_rbac_loaded();
            }
            Ok(WatcherEvent::Apply(cm)) => {
                let rv = cm.metadata.resource_version.clone();
                if rv.is_some() && rv == last_resource_version {
                    continue;
                }
                let doc = cm
                    .data
                    .as_ref()
                    .and_then(|data| data.get(RBAC_CONFIGMAP_KEY))
                    .cloned();
                let outcome = store.apply_event(RbacConfigMapEvent::Applied(doc));
                if outcome == RbacReloadOutcome::Ok {
                    last_resource_version = rv;
                }
                metrics.record_rbac_reload(outcome);
            }
            Ok(WatcherEvent::Delete(_)) => {
                last_resource_version = None;
                let outcome = store.apply_event(RbacConfigMapEvent::Deleted);
                metrics.record_rbac_reload(outcome);
            }
            Err(error) => {
                tracing::warn!(
                    namespace = %namespace,
                    configmap = RBAC_CONFIGMAP_NAME,
                    error = %error,
                    "RBAC ConfigMap watch error; retrying with backoff while retaining active policy"
                );
                metrics.record_rbac_watch_error();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};

    use super::*;
    use crate::state::MAX_GRAPH_LIST_REQUESTS;

    fn owner(kind: &str, name: &str) -> OwnerReference {
        OwnerReference {
            api_version: "apps/v1".to_owned(),
            kind: kind.to_owned(),
            name: name.to_owned(),
            uid: "uid".to_owned(),
            ..OwnerReference::default()
        }
    }

    fn replica_set(name: &str, owner_kind: &str, owner_name: &str) -> ReplicaSet {
        ReplicaSet {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                owner_references: Some(vec![owner(owner_kind, owner_name)]),
                ..ObjectMeta::default()
            },
            ..ReplicaSet::default()
        }
    }

    fn pod(name: &str, replica_set: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_owned()),
                owner_references: Some(vec![owner("ReplicaSet", replica_set)]),
                ..ObjectMeta::default()
            },
            ..Pod::default()
        }
    }

    #[tokio::test]
    async fn rbac_configmap_watch_is_namespaced_and_never_cluster_wide()
    -> Result<(), Box<dyn std::error::Error>> {
        ferriscd_controller::impersonation::ensure_crypto_provider();
        let config = kube::Config::new("https://127.0.0.1:1".parse()?);
        let client = Client::try_from(config)?;

        let default = rbac_configmap_api(client.clone(), "ferriscd-system");
        assert_eq!(
            default.namespace(),
            Some("ferriscd-system"),
            "the RBAC watch must be scoped to the control-plane namespace"
        );

        let custom = rbac_configmap_api(client, "custom-plane");
        assert_eq!(
            custom.namespace(),
            Some("custom-plane"),
            "the RBAC watch must follow --namespace"
        );
        Ok(())
    }

    #[test]
    fn an_owner_reference_match_requires_kind_and_name() {
        let listed = ListedNode::new(
            "api-abc",
            owner_pairs(&replica_set("api-abc", "Deployment", "api")),
        );
        assert!(listed.owned_by("Deployment", "api"));
        assert!(!listed.owned_by("Deployment", "api-2"));
        assert!(!listed.owned_by("StatefulSet", "api"));
        // A child with no owner references is owned by nothing.
        let orphan = ListedNode::new("loose", owner_pairs(&ReplicaSet::default()));
        assert!(orphan.owners.is_empty());
        assert!(!orphan.owned_by("Deployment", "api"));
    }

    #[test]
    fn ownership_labels_are_stable_and_never_carry_the_foreign_id() {
        assert_eq!(
            ownership_label(&ferriscd_engine::inventory::Ownership::OwnedBySelf),
            "OwnedBySelf"
        );
        assert_eq!(
            ownership_label(&ferriscd_engine::inventory::Ownership::Unmanaged),
            "Unmanaged"
        );
        let foreign = ferriscd_engine::inventory::Ownership::OwnedByForeign(
            "other/app:apps/Deployment/ns/x".to_owned(),
        );
        assert_eq!(ownership_label(&foreign), "OwnedByForeign");
    }

    #[test]
    fn every_listing_is_bounded() {
        for kind in [GraphListKind::ReplicaSet, GraphListKind::Pod] {
            assert_eq!(
                kind.params().limit,
                Some(GRAPH_LIST_LIMIT),
                "a namespace with 10 000 {}s must not produce an unbounded list",
                kind.label()
            );
        }
        assert_eq!(list_kind_for("Deployment"), Some(GraphListKind::ReplicaSet));
        assert_eq!(
            list_kind_for("StatefulSet"),
            Some(GraphListKind::ReplicaSet)
        );
        assert_eq!(list_kind_for("DaemonSet"), Some(GraphListKind::ReplicaSet));
        assert_eq!(list_kind_for("ReplicaSet"), Some(GraphListKind::Pod));
        assert_eq!(list_kind_for("ConfigMap"), None);
        assert_eq!(list_kind_for("Pod"), None);
        assert_eq!(child_group(GraphListKind::ReplicaSet), "apps");
        assert_eq!(child_group(GraphListKind::Pod), "");
    }

    /// Records every listing it is asked for, so the graph's cost is asserted, not assumed.
    #[derive(Debug, Default)]
    struct CountingLister {
        replica_sets: Vec<ReplicaSet>,
        pods: Vec<Pod>,
        asked: Mutex<Vec<(String, String, &'static str)>>,
    }

    impl CountingLister {
        fn asked(&self) -> Vec<(String, String, &'static str)> {
            self.asked.lock().expect("test state").clone()
        }
    }

    impl WorkloadNodeLister for CountingLister {
        fn list(
            &self,
            cluster: &str,
            namespace: &str,
            kind: GraphListKind,
        ) -> SeamFuture<'_, Vec<ListedNode>> {
            self.asked.lock().expect("test state").push((
                cluster.to_owned(),
                namespace.to_owned(),
                kind.label(),
            ));
            let listed = match kind {
                GraphListKind::ReplicaSet => self
                    .replica_sets
                    .iter()
                    .map(|object| ListedNode::new(object.name_any(), owner_pairs(object)))
                    .collect(),
                GraphListKind::Pod => self
                    .pods
                    .iter()
                    .map(|object| ListedNode::new(object.name_any(), owner_pairs(object)))
                    .collect(),
            };
            Box::pin(async move { Ok(listed) })
        }
    }

    fn graph_request<'a>(
        cluster: &'a str,
        namespace: &'a str,
        kind: &'a str,
        name: &'a str,
    ) -> GraphRequest<'a> {
        GraphRequest {
            cluster,
            namespace,
            kind,
            name,
        }
    }

    /// **`T14.1` verification + finding `P14-H2`:** several workloads in one namespace cost **one**
    /// `ReplicaSet` list per request, and the pods of several `ReplicaSet`s cost **one** `Pod` list —
    /// the listing is cached per `(cluster, namespace, kind)` and owner references are matched in
    /// memory. A pre-fix implementation issued one list per workload (4 lists where this asserts 2).
    #[tokio::test]
    async fn several_deployments_cost_one_list_per_kind_and_namespace() {
        let lister = Arc::new(CountingLister {
            replica_sets: vec![
                replica_set("api-abc", "Deployment", "api"),
                replica_set("api-def", "Deployment", "api"),
                replica_set("worker-xyz", "Deployment", "worker"),
                replica_set("cron-1", "Deployment", "cron"),
                // A foreign ReplicaSet nobody in this request owns: listed, never returned.
                replica_set("other-1", "Deployment", "someone-else"),
            ],
            pods: vec![
                pod("api-abc-1", "api-abc"),
                pod("api-def-1", "api-def"),
                pod("worker-xyz-1", "worker-xyz"),
            ],
            asked: Mutex::default(),
        });
        let source = KubeWorkloadGraphSource::with_lister(lister.clone());
        let traversal = GraphTraversal::new();

        let mut children = Vec::new();
        for name in ["api", "worker", "cron"] {
            children.push(
                source
                    .children(
                        &traversal,
                        &graph_request("in-cluster", "payments", "Deployment", name),
                    )
                    .await
                    .expect("the deployment's children"),
            );
        }
        assert_eq!(
            lister.asked(),
            vec![("in-cluster".to_owned(), "payments".to_owned(), "ReplicaSet")],
            "three Deployments in one namespace must cost exactly one listing"
        );
        assert_eq!(
            children[0]
                .iter()
                .map(|child| child.key.canonical())
                .collect::<Vec<_>>(),
            vec![
                "apps/ReplicaSet/payments/api-abc".to_owned(),
                "apps/ReplicaSet/payments/api-def".to_owned(),
            ],
            "owner references are matched in memory, per parent"
        );
        assert_eq!(children[1].len(), 1);
        assert_eq!(children[2].len(), 1);
        assert!(
            children
                .iter()
                .flatten()
                .all(|child| child.key.name != "other-1"),
            "a ReplicaSet of another Deployment is never a child"
        );

        // The pod level: two different ReplicaSets, still one `Pod` listing.
        for replica_set_name in ["api-abc", "api-def"] {
            let pods = source
                .children(
                    &traversal,
                    &graph_request("in-cluster", "payments", "ReplicaSet", replica_set_name),
                )
                .await
                .expect("the replica set's pods");
            assert_eq!(pods.len(), 1, "{replica_set_name}");
            assert_eq!(pods[0].key.canonical(), {
                format!("/Pod/payments/{replica_set_name}-1")
            });
        }
        assert_eq!(
            lister.asked(),
            vec![
                ("in-cluster".to_owned(), "payments".to_owned(), "ReplicaSet"),
                ("in-cluster".to_owned(), "payments".to_owned(), "Pod"),
            ],
            "the whole two-level traversal costs two listings"
        );
        assert_eq!(traversal.listings_issued(), 2);
        assert!(!traversal.is_exhausted());

        // A second namespace is a second listing (a cache shared across namespaces would be wrong).
        source
            .children(
                &traversal,
                &graph_request("in-cluster", "billing", "Deployment", "api"),
            )
            .await
            .expect("another namespace");
        assert_eq!(traversal.listings_issued(), 3);

        // A kind that owns no pods never reaches the cluster at all.
        let before = lister.asked().len();
        let none = source
            .children(
                &traversal,
                &graph_request("in-cluster", "payments", "ConfigMap", "settings"),
            )
            .await
            .expect("no children");
        assert!(none.is_empty());
        assert_eq!(lister.asked().len(), before, "a ConfigMap lists nothing");
    }

    /// **Trap guard (finding `P14-H2`):** the request-wide listing budget is a hard ceiling — a
    /// pathological application stops reading the cluster instead of walking it forever, and the
    /// traversal reports that it did.
    #[tokio::test]
    async fn the_traversal_stops_at_the_listing_budget() {
        let lister = Arc::new(CountingLister::default());
        let source = KubeWorkloadGraphSource::with_lister(lister.clone());
        let traversal = GraphTraversal::new();

        for index in 0..MAX_GRAPH_LIST_REQUESTS + 5 {
            let namespace = format!("namespace-{index}");
            let children = source
                .children(
                    &traversal,
                    &graph_request("in-cluster", &namespace, "Deployment", "api"),
                )
                .await
                .expect("an exhausted traversal is not an error");
            assert!(children.is_empty());
        }
        assert_eq!(
            lister.asked().len(),
            MAX_GRAPH_LIST_REQUESTS,
            "the cluster is never read beyond the budget"
        );
        assert!(traversal.is_exhausted());
    }

    fn rbac_configmap(rv: Option<&str>, policy_yaml: Option<&str>) -> ConfigMap {
        let data = policy_yaml.map(|doc| {
            std::collections::BTreeMap::from([(RBAC_CONFIGMAP_KEY.to_owned(), doc.to_owned())])
        });
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(RBAC_CONFIGMAP_NAME.to_owned()),
                namespace: Some("ferriscd-system".to_owned()),
                resource_version: rv.map(ToOwned::to_owned),
                ..ObjectMeta::default()
            },
            data,
            ..ConfigMap::default()
        }
    }

    fn rbac_watch_error_count(metrics: &Metrics) -> u64 {
        let encoded = metrics.encode().expect("metrics encode");
        let prefix = "ferriscd_rbac_watch_errors_total ";
        encoded
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .expect("rbac watch error series must be registered")
    }

    fn rbac_reload_count(metrics: &Metrics, outcome: &str) -> u64 {
        let encoded = metrics.encode().expect("metrics encode");
        let prefix = format!(r#"ferriscd_rbac_reload_total{{outcome="{outcome}"}} "#);
        encoded
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .expect("rbac reload series must be pre-registered")
    }

    /// **`T17.1`:** `drive_rbac_watch` marks the RBAC readiness gate on `InitDone`, activates the
    /// initial policy, and suppresses the startup `ok` counter increment so routine boot is not
    /// miscounted as a live reload.
    #[tokio::test]
    async fn drive_rbac_watch_marks_readiness_on_init_done_and_suppresses_startup_ok_metric() {
        let (tx, mut rx) =
            tokio::sync::mpsc::unbounded_channel::<Result<WatcherEvent<ConfigMap>, &'static str>>();
        let stream = futures::stream::poll_fn(move |cx| rx.poll_recv(cx));
        let store = RbacPolicyStore::empty();
        let readiness = ControlPlaneReadiness::new();
        readiness.mark_controllers_ready();
        readiness.mark_clusters_seeded();
        let metrics = Metrics::with_fixed_series();
        let stop = CancellationToken::new();

        let task = tokio::spawn(drive_rbac_watch(
            stream,
            "ferriscd-system",
            store.clone(),
            readiness.clone(),
            metrics.clone(),
            stop.clone(),
        ));

        let policy_v1 = r#"
rules:
  - subject: { kind: group, name: payments-dev }
    project: payments
    actions: [get]
"#;
        tx.send(Ok(WatcherEvent::Init)).expect("send Init");
        tx.send(Ok(WatcherEvent::InitApply(rbac_configmap(
            Some("10"),
            Some(policy_v1),
        ))))
        .expect("send InitApply");
        tokio::task::yield_now().await;
        assert!(
            !readiness.is_ready(),
            "readiness must stay false until InitDone completes"
        );

        tx.send(Ok(WatcherEvent::InitDone)).expect("send InitDone");
        drop(tx);
        task.await.expect("watch task finishes cleanly");

        assert!(
            readiness.is_ready(),
            "InitDone must flip the RBAC readiness gate to ready"
        );
        let identity = AuthenticatedIdentity::new("alice", vec!["payments-dev".to_owned()]);
        assert!(
            store
                .snapshot()
                .grants(&identity, "payments")
                .allows(crate::rbac::Action::Get)
        );
        assert_eq!(
            rbac_reload_count(&metrics, "ok"),
            0,
            "initial InitApply must not inflate live reload ok counter"
        );
        assert_eq!(rbac_reload_count(&metrics, "error"), 0);
        assert_eq!(rbac_reload_count(&metrics, "deleted"), 0);
    }

    /// **`T17.1`:** routine watch reconnects (`410 Gone` re-lists) and duplicate `Apply` events
    /// carrying the already-active `resourceVersion` must neither re-parse nor inflate
    /// `ferriscd_rbac_reload_total`, while a genuinely new `resourceVersion` hot-reloads immediately.
    #[tokio::test]
    async fn drive_rbac_watch_deduplicates_unchanged_resource_version_and_reloads_updates() {
        let policy_v1 = r#"
rules:
  - subject: { kind: group, name: payments-dev }
    project: payments
    actions: [get]
"#;
        let policy_v2 = r#"
rules:
  - subject: { kind: group, name: payments-dev }
    project: payments
    actions: [get, sync]
"#;
        let events: Vec<Result<WatcherEvent<ConfigMap>, &'static str>> = vec![
            Ok(WatcherEvent::Init),
            Ok(WatcherEvent::InitApply(rbac_configmap(
                Some("10"),
                Some(policy_v1),
            ))),
            Ok(WatcherEvent::InitDone),
            // Reconnect re-list with the exact same RV: must be deduplicated.
            Ok(WatcherEvent::Init),
            Ok(WatcherEvent::InitApply(rbac_configmap(
                Some("10"),
                Some(policy_v1),
            ))),
            Ok(WatcherEvent::InitDone),
            // Duplicate Apply with the exact same RV: must be deduplicated.
            Ok(WatcherEvent::Apply(rbac_configmap(
                Some("10"),
                Some(policy_v1),
            ))),
            // Real policy edit at RV 11: must hot-reload and count exactly once.
            Ok(WatcherEvent::Apply(rbac_configmap(
                Some("11"),
                Some(policy_v2),
            ))),
        ];

        let store = RbacPolicyStore::empty();
        let readiness = ControlPlaneReadiness::new();
        let metrics = Metrics::with_fixed_series();
        let stop = CancellationToken::new();

        drive_rbac_watch(
            futures::stream::iter(events),
            "ferriscd-system",
            store.clone(),
            readiness,
            metrics.clone(),
            stop,
        )
        .await;

        let identity = AuthenticatedIdentity::new("alice", vec!["payments-dev".to_owned()]);
        assert!(
            store
                .snapshot()
                .grants(&identity, "payments")
                .allows(crate::rbac::Action::Sync)
        );
        assert_eq!(rbac_reload_count(&metrics, "ok"), 1);
        assert_eq!(rbac_reload_count(&metrics, "error"), 0);
        assert_eq!(rbac_reload_count(&metrics, "deleted"), 0);
    }

    /// **`T17.1`:** malformed YAML updates, missing `policy.yaml` keys, and transient watch stream
    /// errors must retain the last known-good policy and record `outcome="error"` without breaking
    /// readiness or existing grants.
    #[tokio::test]
    async fn drive_rbac_watch_retains_last_good_on_malformed_updates_and_watch_errors() {
        let valid = r#"
rules:
  - subject: { kind: group, name: payments-dev }
    project: payments
    actions: [get]
"#;
        let events: Vec<Result<WatcherEvent<ConfigMap>, &'static str>> = vec![
            Ok(WatcherEvent::Init),
            Ok(WatcherEvent::InitApply(rbac_configmap(
                Some("10"),
                Some(valid),
            ))),
            Ok(WatcherEvent::InitDone),
            // Malformed YAML at RV 11 -> retain RV 10, increment error.
            Ok(WatcherEvent::Apply(rbac_configmap(
                Some("11"),
                Some("rules: [unterminated"),
            ))),
            // Missing policy.yaml key at RV 12 -> retain RV 10, increment error.
            Ok(WatcherEvent::Apply(rbac_configmap(Some("12"), None))),
            // Transient watch error -> retain RV 10, do not crash or clear store.
            Err("simulated watch disconnect"),
        ];

        let store = RbacPolicyStore::empty();
        let readiness = ControlPlaneReadiness::new();
        let metrics = Metrics::with_fixed_series();
        let stop = CancellationToken::new();

        drive_rbac_watch(
            futures::stream::iter(events),
            "ferriscd-system",
            store.clone(),
            readiness,
            metrics.clone(),
            stop,
        )
        .await;

        let identity = AuthenticatedIdentity::new("alice", vec!["payments-dev".to_owned()]);
        assert!(
            store
                .snapshot()
                .grants(&identity, "payments")
                .allows(crate::rbac::Action::Get),
            "last known-good policy must remain active after malformed updates and watch errors"
        );
        assert_eq!(rbac_reload_count(&metrics, "ok"), 0);
        assert_eq!(
            rbac_reload_count(&metrics, "error"),
            2,
            "malformed updates alone must drive the reload error counter"
        );
        assert_eq!(
            rbac_watch_error_count(&metrics),
            2,
            "the stream error and the trailing stream end must be visible on the dedicated counter"
        );
        assert_eq!(rbac_reload_count(&metrics, "deleted"), 0);
    }

    /// **`T17.1`:** deleting `ferriscd-rbac-cm` directly (`Delete`) or omitting it from a completed
    /// reconnect re-list (`Init` -> `InitDone` without `InitApply`) must fail closed to
    /// `RbacPolicy::empty()` and increment `outcome="deleted"` once per transition.
    #[tokio::test]
    async fn drive_rbac_watch_fails_closed_on_delete_and_relist_omission() {
        let valid = r#"
rules:
  - subject: { kind: group, name: payments-dev }
    project: payments
    actions: [get]
"#;
        let events: Vec<Result<WatcherEvent<ConfigMap>, &'static str>> = vec![
            // Startup loads RV 10.
            Ok(WatcherEvent::Init),
            Ok(WatcherEvent::InitApply(rbac_configmap(
                Some("10"),
                Some(valid),
            ))),
            Ok(WatcherEvent::InitDone),
            // Explicit Delete -> fail closed (deleted = 1).
            Ok(WatcherEvent::Delete(rbac_configmap(
                Some("11"),
                Some(valid),
            ))),
            // Re-created at RV 12 -> live reload (ok = 1).
            Ok(WatcherEvent::Apply(rbac_configmap(Some("12"), Some(valid)))),
            // Deleted while disconnected; reconnect re-list sees nothing -> fail closed (deleted = 2).
            Ok(WatcherEvent::Init),
            Ok(WatcherEvent::InitDone),
            // Another empty re-list while already empty -> must not double-count deleted.
            Ok(WatcherEvent::Init),
            Ok(WatcherEvent::InitDone),
        ];

        let store = RbacPolicyStore::empty();
        let readiness = ControlPlaneReadiness::new();
        let metrics = Metrics::with_fixed_series();
        let stop = CancellationToken::new();

        drive_rbac_watch(
            futures::stream::iter(events),
            "ferriscd-system",
            store.clone(),
            readiness,
            metrics.clone(),
            stop,
        )
        .await;

        assert!(
            store.is_empty(),
            "store must fail closed to empty after deletion / re-list omission"
        );
        assert_eq!(rbac_reload_count(&metrics, "ok"), 1);
        assert_eq!(rbac_reload_count(&metrics, "error"), 0);
        assert_eq!(rbac_reload_count(&metrics, "deleted"), 2);
    }

    /// **`T17.1`:** cancelling the shutdown token exits `drive_rbac_watch` promptly even while the
    /// underlying stream is idle.
    #[tokio::test]
    async fn drive_rbac_watch_stops_promptly_on_cancellation() {
        let stop = CancellationToken::new();
        let cancel_handle = stop.clone();
        let stream = futures::stream::pending::<Result<WatcherEvent<ConfigMap>, &'static str>>();
        let task = tokio::spawn(drive_rbac_watch(
            stream,
            "ferriscd-system",
            RbacPolicyStore::empty(),
            ControlPlaneReadiness::new(),
            Metrics::with_fixed_series(),
            stop,
        ));
        cancel_handle.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("watch task must exit promptly on cancellation")
            .expect("watch task must not panic");
    }
}
