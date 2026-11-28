//! The REST API: routes, handlers, and the DTOs the OpenAPI contract freezes.
//!
//! Four route groups, deliberately disjoint (see [`crate::auth`]):
//!
//! ```text
//! public      GET  /healthz
//!             GET  /readyz
//!             GET  /api/v1/auth/config             (T19.1 sign-in discovery)
//! sessions    GET  /api/v1/auth/login              (T19.2 BFF; 404 unless --oidc-bff-enabled)
//!             GET  /api/v1/auth/callback           (state cookie must match the query parameter)
//!             POST /api/v1/auth/logout             (CSRF double-submit required)
//! webhooks    POST /api/v1/webhooks/github         (HMAC-authenticated, T14.2)
//!             POST /api/v1/webhooks/gitlab         (token-authenticated, T14.2)
//! protected   GET  /api/v1/applications
//!             GET  /api/v1/applications/stream
//!             GET  /api/v1/applications/{ns}/{name}
//!             GET  /api/v1/applications/{ns}/{name}/resources
//!             GET  /api/v1/applications/{ns}/{name}/diff
//!             GET  /api/v1/applications/{ns}/{name}/events
//!             POST /api/v1/applications/{ns}/{name}/sync
//!             POST /api/v1/applications/{ns}/{name}/rollback
//!             GET  /api/v1/projects
//!             GET  /api/v1/applicationsets
//!             GET  /api/v1/clusters
//!             GET  /api/v1/openapi.json
//! ```
//!
//! Every handler is a thin adapter over a [`crate::state`] seam and does exactly three things:
//! read, call one seam, map the result. Nothing is cached, nothing is persisted, and no handler
//! mutates an `Application` except `sync`/`rollback`, which patch one annotation so the **controller**
//! performs the work (finding C9: the API never re-implements the engine, and never stores state to
//! avoid doing so).
//!
//! `ferriscd.io/operation` is a **single slot** that the controller consumes once a pass has settled
//! (`{"sync":{}}` after a manual sync, `{"rollback":{"id":N}}` after the rollback is applied). The
//! operation handlers therefore work with a *pending* request rather than refusing one: a repeated
//! sync is an idempotent `202`, a rollback supersedes whatever is there, and only an unconsumed
//! rollback followed by a sync is a `409` (finding `P14-C1`).
//!
//! Every failure — including a rejected body — is the one `{"error":{"code","message"}}` shape
//! ([`crate::error`]); the handlers take `Bytes` and parse it themselves so an oversized body is the
//! documented `413` and a malformed one never echoes what was sent (finding `P14-M1`).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Extension, Path, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ferriscd_crd::annotations;
use ferriscd_crd::status::{
    ApplicationStatus, ConditionStatus, HealthState, OperationPhase, RevisionHistoryEntry,
};
use ferriscd_crd::{AppProject, Application};
use ferriscd_engine::diff::ResourceDiff;
use ferriscd_engine::manifest::ResourceKey;
use ferriscd_engine::policy::{SyncWindowSet, SyncWindowTarget};
use futures::StreamExt as _;
use futures::stream::BoxStream;
use k8s_openapi::jiff::Timestamp;
use kube::ResourceExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::audit::{
    self, AuditOutcome, RequestId, TokenFingerprint, record_api_operation, record_rbac_denied,
};
use crate::auth::{self, AuthenticatedIdentity};
use crate::auth_bff;
use crate::error::{ApiError, ApiErrorBody};
use crate::openapi;
use crate::rbac::{Action, Actor, RbacPolicyStore};
use crate::state::{
    AppState, ApplicationEvent, ClusterEntry, GraphRequest, GraphTraversal, MAX_APPLICATION_EVENTS,
    MAX_GRAPH_LIST_REQUESTS, OperationRequest,
};
use crate::webhooks;

/// Hard cap on the nodes of one `GET .../resources` response.
///
/// A bundle with thousands of resources (or a runaway `ReplicaSet` history) must not be able to
/// produce an unbounded payload: the graph stops here and says so
/// ([`ResourceGraphView::truncated`]).
pub const MAX_GRAPH_NODES: usize = 500;

/// Workload kinds whose children are discovered through `metadata.ownerReferences`.
///
/// Nothing else is traversed: a `Service`/`ConfigMap` has no owned pods, and wandering through
/// arbitrary owner references would turn one request into a cluster-wide walk (ADR-004 forbids
/// background informers; this keeps the *on-demand* read equally narrow).
const TRAVERSABLE_KINDS: [&str; 3] = ["Deployment", "StatefulSet", "DaemonSet"];

/// Kinds whose children are traversed one more level (`ReplicaSet -> Pod`).
const SECOND_LEVEL_KINDS: [&str; 1] = ["ReplicaSet"];

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Liveness answer.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    /// Always `ok` while the process answers.
    pub status: String,
}

/// Readiness answer.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReadyResponse {
    /// `ready` or `not ready`.
    pub status: String,
    /// Why it is not ready.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `GET /api/v1/applications` body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationListView {
    /// Every watched `Application`.
    pub items: Vec<ApplicationSummary>,
}

/// One `Application`, reduced to what a UI/CLI lists.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSummary {
    /// `metadata.namespace`.
    pub namespace: String,
    /// `metadata.name`.
    pub name: String,
    /// `spec.project`.
    pub project: String,
    /// `spec.source` summary (the repository URL is redacted).
    pub source: SourceView,
    /// `spec.destination`.
    pub destination: DestinationView,
    /// `status.sync` (absent before the first reconcile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncView>,
    /// `status.health`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthView>,
    /// `status.conditions`, newest last, exactly as the controller wrote them.
    #[serde(default)]
    pub conditions: Vec<ConditionView>,
    /// How many resources `status.inventory` tracks.
    pub resource_count: usize,
    /// `status.observedGeneration`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// `metadata.labels["ferriscd.io/applicationset"]`: the `ApplicationSet` that generated this
    /// `Application` (`T19.3`). Absent for a hand-authored one, which is what the web UI badges on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicationset: Option<String>,
}

/// The `sourceType` value assumed for a payload that predates the field (`T18.4`).
///
/// A `v1.1` server only serves Git sources, so `git` is the honest default rather than an error
/// that would make an upgraded CLI unusable against a not-yet-upgraded control plane.
fn git_source_type() -> String {
    "git".to_owned()
}

/// `spec.source` summary.
///
/// `T18.4` added the source **kind** and, for an OCI artifact, its `tag` and pinned `digest`. The
/// fields are additive: a Git `Application` keeps `sourceType: "git"` with no `tag`/`digest` key at
/// all, so an existing client sees exactly the payload it saw before.
///
/// **Client/server skew (finding M6).** `sourceType` is *new*, so a `v1.1` server does not send it.
/// Deserializing therefore defaults to `"git"` (the only source kind that version could serve)
/// instead of failing the whole response, while the **response** schema keeps the field required
/// (`#[schema(required = true)]`) — a `v1.2` server always fills it in, and the generated
/// TypeScript client must keep treating it as present.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceView {
    /// Source kind (`git` or `oci`).
    ///
    /// Defaults to `git` when absent: an older server has no OCI support, so every source it can
    /// report *is* a Git source.
    #[serde(default = "git_source_type")]
    #[schema(required = true)]
    pub source_type: String,
    /// Repository or registry URL, redacted (a remote URL may carry a token).
    pub repo_url: String,
    /// Path inside the repository (`""` for its root).
    pub path: String,
    /// Requested revision (`spec.source.git.targetRevision`, else `oci.tag`, else `oci.digest`).
    pub target_revision: String,
    /// OCI tag to resolve (`spec.source.oci.tag`); absent for a Git source and for a digest-only
    /// reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Pinned OCI manifest digest (`spec.source.oci.digest`, `sha256:<64-hex>`); never set by a
    /// resolution — this is what the `Application` *pinned*, not what the registry answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Selected renderer (`auto`, `plainYaml`, `kustomize`, `helm`).
    pub renderer: String,
}

/// `spec.destination`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DestinationView {
    /// `spec.destination.cluster`.
    pub cluster: String,
    /// `spec.destination.namespace`.
    pub namespace: String,
}

/// `status.sync`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncView {
    /// `Synced` or `OutOfSync`.
    pub status: String,
    /// Revision the last pass rendered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Revision of the last **settled** sync.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_revision: Option<String>,
    /// When that settled sync happened (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<String>,
}

/// `status.health`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthView {
    /// `Healthy`, `Progressing`, `Degraded`, `Suspended`, `Missing`, or `Unknown`.
    pub status: String,
    /// Bounded human-readable message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One `status.conditions` entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConditionView {
    /// Condition type (`Ready`).
    #[serde(rename = "type")]
    pub type_: String,
    /// `True`, `False`, or `Unknown`.
    pub status: String,
    /// Machine-readable reason.
    pub reason: String,
    /// Human-readable message.
    pub message: String,
    /// When the status last changed (RFC 3339).
    pub last_transition_time: String,
    /// `metadata.generation` observed when the condition was computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// One `status.history` entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct HistoryView {
    /// Deployment id (the `{"rollback":{"id":N}}` handle).
    pub id: i64,
    /// The commit that was deployed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// When it was deployed (RFC 3339).
    pub deployed_at: String,
}

/// `status.operationState`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationView {
    /// `Running`, `Succeeded`, `Failed`, or `Error`.
    pub phase: String,
    /// Sync wave currently being applied.
    pub current_wave: i32,
    /// Revision the operation is working on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// When it started (RFC 3339).
    pub started_at: String,
    /// When it finished (RFC 3339), absent while running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    /// Bounded progress/error message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `GET /api/v1/applications/{namespace}/{name}` body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationDetailView {
    /// The application itself.
    pub application: ApplicationSummary,
    /// Last `status.history` entries, oldest first.
    #[serde(default)]
    pub history: Vec<HistoryView>,
    /// The running operation, when one is recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationView>,
    /// The `AppProject` sync-window verdict for this `Application` right now (`T17.4`).
    ///
    /// Absent when the project configures no window: a project without governance windows adds
    /// nothing to the payload. (`ApplicationDetailView` has no `rename_all`, so the wire name is
    /// spelled out here to stay camelCase like the rest of the API.)
    #[serde(
        rename = "syncWindow",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sync_window: Option<SyncWindowGateView>,
}

/// One node of the resource graph.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceNodeView {
    /// Version-agnostic GKNN key (`group/kind/namespace/name`).
    pub key: String,
    /// API group (empty for the core group).
    pub group: String,
    /// Resource kind.
    pub kind: String,
    /// Namespace, absent for cluster-scoped resources.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Object name.
    pub name: String,
    /// Whether the object exists in the destination cluster right now.
    pub present: bool,
    /// Ownership verdict for a present object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership: Option<String>,
    /// Per-resource health from the last reconcile (`status.resourceStatuses`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    /// The health message of the last reconcile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_message: Option<String>,
    /// GKNN of the owning node (`Deployment -> ReplicaSet -> Pod`), absent for roots.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

/// `GET /api/v1/applications/{namespace}/{name}/resources` body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceGraphView {
    /// Namespace the graph was read from (`spec.destination.namespace`).
    pub namespace: String,
    /// Cluster the graph was read from (`spec.destination.cluster`).
    pub cluster: String,
    /// `Application.status.sync.status` — the per-application sync verdict.
    pub sync_status: String,
    /// `Application.status.health.status`.
    pub health_status: String,
    /// Inventory nodes plus discovered `Deployment -> ReplicaSet -> Pod` children.
    pub nodes: Vec<ResourceNodeView>,
    /// Whether the response was cut at [`MAX_GRAPH_NODES`].
    pub truncated: bool,
}

/// One field-level change of a diffed resource.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiffChangeView {
    /// RFC 6901 JSON Pointer into the redacted object.
    pub path: String,
    /// `added`, `removed`, or `modified`.
    pub kind: String,
    /// Live value at `path`, already redacted.
    #[schema(value_type = Option<Object>)]
    pub live: Option<serde_json::Value>,
    /// Predicted value at `path`, already redacted.
    #[schema(value_type = Option<Object>)]
    pub predicted: Option<serde_json::Value>,
}

/// One Server-Side Apply field-ownership conflict.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiffConflictView {
    /// The disputed field, as reported by the API server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The manager that owns the field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
}

/// One diffed resource.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiffResourceView {
    /// Version-agnostic GKNN key.
    pub key: String,
    /// `Synced`, `OutOfSync`, `Missing`, `Orphaned`, or `OwnershipConflict`.
    pub status: String,
    /// The foreign owner, when `status` is `OwnershipConflict`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The field changes, already `Secret`-redacted and `ignoreDifferences`-filtered.
    #[serde(default)]
    pub changes: Vec<DiffChangeView>,
    /// Field-ownership conflicts.
    #[serde(default)]
    pub conflicts: Vec<DiffConflictView>,
    /// Whether the change list was cut by the engine's bound.
    pub truncated: bool,
}

/// Aggregate counts of a diff.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiffSummaryView {
    /// Resources classified.
    pub total: usize,
    /// Resources whose live state matches the prediction.
    pub synced: usize,
    /// Resources that differ.
    pub out_of_sync: usize,
    /// Resources that do not exist yet.
    pub missing: usize,
    /// Tracked resources no longer in Git.
    pub orphaned: usize,
    /// Resources owned by another `Application`.
    pub ownership_conflicts: usize,
    /// Field-ownership conflicts.
    pub field_conflicts: usize,
}

/// `GET /api/v1/applications/{namespace}/{name}/diff` body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct DiffView {
    /// Commit the desired state was rendered from.
    pub revision: String,
    /// How many resources the rendered bundle contains.
    pub desired: usize,
    /// Whether the sync decision gate would apply this set right now.
    pub would_sync: bool,
    /// Counts over [`Self::resources`].
    pub summary: DiffSummaryView,
    /// One entry per resource in `desired ∪ status.inventory`.
    #[serde(default)]
    pub resources: Vec<DiffResourceView>,
}

/// `POST .../sync` request body.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncRequestBody {
    /// Pin the sync to a specific revision. **Not supported in `v1.0`** (see [`sync_application`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    /// Prune orphans after the sync. **Not supported in `v1.0`**: pruning is a spec field
    /// (`syncPolicy.automated.prune`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prune: Option<bool>,
    /// Compute the sync without applying it. **Not supported in `v1.0`**: that is `GET .../diff`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
}

/// `POST .../rollback` request body.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct RollbackRequestBody {
    /// `status.history[].id` to redeploy.
    pub id: i64,
}

/// What a `sync`/`rollback` request did.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationResponse {
    /// Always `accepted` (the controller performs the work).
    pub status: String,
    /// `sync` or `rollback`.
    pub operation: String,
    /// Namespace of the `Application`.
    pub namespace: String,
    /// Name of the `Application`.
    pub name: String,
    /// The exact `ferriscd.io/operation` value that was patched.
    pub request: String,
    /// The resource version the patch was conditioned on, when it was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_version: Option<String>,
}

/// `GET /api/v1/projects` body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProjectListView {
    /// Every `AppProject` of the control-plane namespace.
    pub items: Vec<ProjectView>,
}

/// One `AppProject`, reduced to its boundary facts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectView {
    /// `metadata.name`.
    pub name: String,
    /// `spec.description`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `spec.sourceRepos`.
    #[serde(default)]
    pub source_repos: Vec<String>,
    /// `spec.sourceNamespaces`.
    #[serde(default)]
    pub source_namespaces: Vec<String>,
    /// `spec.destinations`, rendered as `cluster/namespace`.
    #[serde(default)]
    pub destinations: Vec<String>,
    /// `spec.allowedServiceAccounts`.
    #[serde(default)]
    pub allowed_service_accounts: Vec<String>,
    /// `spec.syncWindows`, each with its state at the moment of the response (`T17.4`).
    ///
    /// Empty (and omitted) for a project that configures no window, so the pre-`T17.4` payload is
    /// byte-identical for every such project.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync_windows: Vec<ProjectSyncWindowView>,
    /// When the next window starts or stops (RFC 3339), across every configured window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_sync_window_transition: Option<String>,
}

/// One `spec.syncWindows[]` entry with its state at the moment of the response (`T17.4`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSyncWindowView {
    /// `allow` or `deny` (deny wins over allow).
    pub kind: String,
    /// The 5-field cron expression, verbatim.
    pub schedule: String,
    /// The duration, verbatim (`30m`, `2h`, `7d`).
    pub duration: String,
    /// The effective IANA time zone (`UTC` when `spec.syncWindows[].timeZone` is absent).
    pub time_zone: String,
    /// Glob patterns for `Application.metadata.name` (empty = every application).
    #[serde(default)]
    pub applications: Vec<String>,
    /// Glob patterns for `Application.metadata.namespace` (empty = every namespace).
    #[serde(default)]
    pub namespaces: Vec<String>,
    /// Glob patterns for `spec.destination.cluster` (empty = every cluster).
    #[serde(default)]
    pub clusters: Vec<String>,
    /// Whether a manual sync may override this window.
    pub manual_sync: bool,
    /// Whether the window is open right now.
    pub active: bool,
    /// When the currently open occurrence started (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<String>,
    /// When the currently open occurrence ends (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<String>,
    /// The next occurrence that starts after now (RFC 3339), within a year.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_start: Option<String>,
    /// Why this entry cannot be evaluated. The project is deny-all while it is set (fail closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The sync-window verdict for one `Application` right now (`T17.4`).
///
/// The UI needs this to explain a blocked `POST .../sync` *before* the operator clicks: a window is
/// a time-based refusal, and "nothing happened" is indistinguishable from a controller stall
/// otherwise. `manualOverride` says whether a manual sync would be honoured anyway
/// (`manualSync: true` on every blocking window).
///
/// A blocked manual sync is **deferred, not rejected**: the controller pauses the requested
/// operation and runs it when the window lifts, without asking again (finding N-c), so the modal
/// tells the operator *when* it will happen rather than to come back and click twice.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncWindowGateView {
    /// Whether a manual sync would be skipped right now.
    pub blocked: bool,
    /// `denyWindowActive`, `outsideAllowWindow`, or `invalidWindow`; absent when not blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable explanation, including the next window transition.
    pub message: String,
    /// Whether `manualSync: true` makes a manual sync still executable.
    pub manual_override: bool,
    /// When the verdict could change (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_transition: Option<String>,
}

/// `GET /api/v1/clusters` body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ClusterListView {
    /// `in-cluster` first, then every registered cluster name.
    pub items: Vec<ClusterView>,
}

/// One addressable cluster.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterView {
    /// `spec.destination.cluster` name.
    pub name: String,
    /// Whether this is the cluster the control plane runs in.
    pub in_cluster: bool,
}

/// `GET /api/v1/applicationsets` body (`T19.3`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationSetListView {
    /// Every `ApplicationSet` of the control-plane namespace.
    pub items: Vec<ApplicationSetView>,
}

/// One `ApplicationSet`, reduced to its generation facts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSetView {
    /// `metadata.namespace`.
    pub namespace: String,
    /// `metadata.name`.
    pub name: String,
    /// `spec.generators[0]`'s kind (`list`, `git`, `clusters`, `matrix`).
    pub generator: String,
    /// For a `matrix`, the two child generator kinds (empty otherwise).
    #[serde(default)]
    pub matrix: Vec<String>,
    /// `spec.template.spec.project`.
    pub project: String,
    /// `spec.syncPolicy.preserveResourcesOnDeletion` (always present, defaults to `true`).
    pub preserve_resources_on_deletion: bool,
    /// `spec.syncPolicy.prune` (defaults to `false`).
    pub prune: bool,
    /// `status.generatedCount`.
    pub generated_count: u32,
    /// `status.conditions`, newest last.
    #[serde(default)]
    pub conditions: Vec<ConditionView>,
    /// `status.observedGeneration`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// `status` `Ready` condition, `True`/`False`/`Unknown` (absent before the first pass).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ready: Option<String>,
}

/// `GET /api/v1/applications/{namespace}/{name}/events` body (`T17.3`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApplicationEventListView {
    /// The latest events, newest first, at most 50.
    pub items: Vec<ApplicationEventView>,
    /// Whether the cluster holds more events about this `Application` than the `items` list carries.
    pub truncated: bool,
}

/// One Kubernetes `Event` about an `Application`, as the timeline renders it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationEventView {
    /// `metadata.name` of the `Event` object.
    pub name: String,
    /// `type`: `Normal`, `Warning`, or `Unknown`.
    #[serde(rename = "type")]
    pub type_: String,
    /// `reason` (`SyncSucceeded`, `SyncFailed`, `ResourcePruned`, ...).
    pub reason: String,
    /// `note`, redacted: no URL credential, `Secret` payload, or token survives here.
    pub message: String,
    /// `action` (`Sync`, `Prune`, ...), when recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// How many times the event recurred.
    pub count: i32,
    /// `reportingController` — the component that emitted it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reporting_component: Option<String>,
    /// When it was last observed (RFC 3339 UTC), when the cluster recorded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_observed_at: Option<String>,
    /// When it was first observed (RFC 3339 UTC), when the cluster recorded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_observed_at: Option<String>,
}

/// `GET /api/v1/auth/config` body (`T19.1`).
///
/// Served from the **public** group: the SPA and `ferriscd login --oidc` must learn how to
/// authenticate before they have a token, so this carries only what a stranger may know — the auth
/// mode, the issuer, the public client id and the scopes (`T19.2` consumes it).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfigView {
    /// `token-review`, `oidc`, `token-review-or-oidc`, `pass-through` or `deny-all`.
    pub auth_mode: String,
    /// The configured OIDC issuer. **Absent** when OIDC is disabled; never `null`.
    //
    // Finding `N4`: the field is absent — never `null` — when OIDC is off, so the published schema
    // says "an optional string" instead of `string | null`, a third state the server cannot produce.
    // `value_type` keeps the Rust field an `Option` (serde still omits it) while the schema is a
    // plain optional string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = String)]
    pub issuer: Option<String>,
    /// The configured OAuth client id. **Absent** when OIDC is disabled; never `null`.
    //
    // Absent, never `null`, exactly like `issuer` (finding `N4`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = String)]
    pub client_id: Option<String>,
    /// The scopes the client should request from the IdP. Always present (`[]` when OIDC is off).
    //
    // Finding `N4`: the handler always emits this field, so the contract marks it **required**
    // (`scopes: string[]`, not `scopes?: string[]`). That is why there is no `#[serde(default)]`
    // here: the attribute would mark the field optional in the published schema while every
    // response carries it.
    pub scopes: Vec<String>,
    /// Whether the optional server-side (BFF cookie) session mode is enabled (`T19.2`).
    pub bff_enabled: bool,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Builds the whole API router.
///
/// The body limit is installed **once, on the outermost router**, so it applies before any
/// extractor runs — including the webhook handlers, which is what makes an oversized delivery a
/// `413` instead of a parse of a 300 MiB body (`T14.2`).
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/applications", get(list_applications))
        // `T17.3`: the SSE feed is a **fixed** path, registered before the parameterised routes so
        // `stream` can never be read as an `Application` namespace.
        .route("/api/v1/applications/stream", get(stream_applications))
        .route(
            "/api/v1/applications/{namespace}/{name}",
            get(get_application),
        )
        .route(
            "/api/v1/applications/{namespace}/{name}/resources",
            get(get_resources),
        )
        .route(
            "/api/v1/applications/{namespace}/{name}/diff",
            get(get_diff),
        )
        .route(
            "/api/v1/applications/{namespace}/{name}/events",
            get(get_application_events),
        )
        .route(
            "/api/v1/applications/{namespace}/{name}/sync",
            post(sync_application),
        )
        .route(
            "/api/v1/applications/{namespace}/{name}/rollback",
            post(rollback_application),
        )
        .route("/api/v1/projects", get(list_projects))
        // `T19.3`: the read-only `ApplicationSet` view. Generation itself is opt-in in the
        // controller; the API only reports what exists.
        .route("/api/v1/applicationsets", get(list_applicationsets))
        .route("/api/v1/clusters", get(list_clusters))
        .route("/api/v1/openapi.json", get(openapi_document))
        // The `T14.3` seam: one layer installed on the group before it is merged. `axum`'s
        // `route_layer` covers only the routes registered **above** it — add new protected routes
        // before this call, never after. Handlers also extract `Extension<AuthenticatedIdentity>`,
        // so a route that somehow lost the layer fails closed (500) rather than answering.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authenticate,
        ))
        // `T19.2`: when the optional BFF session cookie flow is on, every mutating request that
        // carries that cookie must echo the double-submit CSRF header. Installed on the same route
        // group (and after the routes, like the auth layer) so a new protected POST cannot silently
        // lose it.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_bff::csrf,
        ));

    let public = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // `T19.1`: the sign-in discovery endpoint. It must be reachable **before** a caller has a
        // credential (that is its whole purpose), so it is registered here, in the public group, and
        // never behind the middleware above.
        .route("/api/v1/auth/config", get(auth_config));

    // `T19.2`: the optional BFF routes. Always registered so the OpenAPI document is honest about
    // them; each answers `404` when the server was not started with `--oidc-bff-enabled`. `logout`
    // sits in this group deliberately: it must be reachable with an expired/absent session cookie so
    // a stuck browser can always clear it, and the CSRF layer is installed on the group.
    let auth_sessions = Router::new()
        .route(auth_bff::LOGIN_PATH, get(auth_bff::login))
        .route(auth_bff::CALLBACK_PATH, get(auth_bff::callback))
        .route(auth_bff::LOGOUT_PATH, post(auth_bff::logout))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_bff::csrf,
        ));

    let webhooks = Router::new()
        .route("/api/v1/webhooks/github", post(webhooks::github))
        .route("/api/v1/webhooks/gitlab", post(webhooks::gitlab));

    Router::new()
        .merge(protected)
        .merge(public)
        .merge(auth_sessions)
        .merge(webhooks)
        .layer(DefaultBodyLimit::max(state.webhooks.max_body_bytes()))
        // `T17.2`: outermost correlation layer so every protected handler, 401 auth rejection,
        // and webhook delivery receives a sanitized `X-Request-Id` and echoes it on the response.
        .layer(middleware::from_fn(audit::request_id_middleware))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers: probes
// ---------------------------------------------------------------------------

/// Liveness probe: the process is running and the router answers.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "health",
    responses((status = 200, description = "The API server is alive", body = HealthResponse)),
)]
pub async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
    })
}

/// Readiness probe: `503` until the control plane's startup gates (`Application` watches,
/// `ClusterManager` initial `Secret` seed, and initial `ferriscd-rbac-cm` load) have all completed
/// `InitDone` (`T17.1`).
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "health",
    responses(
        (status = 200, description = "Ready", body = ReadyResponse),
        (status = 503, description = "Not ready", body = ReadyResponse),
    ),
)]
pub async fn readyz(State(state): State<AppState>) -> axum::response::Response {
    use axum::http::HeaderValue;
    use axum::response::IntoResponse as _;

    if state.readiness.is_ready() {
        // The probe evaluation itself (`is_ready`/`reason`) allocates zero heap memory; this branch
        // only wraps a static body (`T17.1` non-functional requirement).
        (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            axum::body::Body::from(r#"{"status":"ready"}"#),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not ready".to_owned(),
                reason: state.readiness.reason(),
            }),
        )
            .into_response()
    }
}

// ---------------------------------------------------------------------------
// Handlers: authentication discovery
// ---------------------------------------------------------------------------

/// Publishes how a caller can authenticate, so the Web UI and the CLI can pick a sign-in flow
/// (`T19.1`; `T19.2` consumes it with PKCE).
///
/// Unauthenticated by design: a client cannot present a credential for a flow it does not know yet.
/// The payload is therefore the *public* half of the configuration only — no CA bundle, no client
/// secret, no token — and [`crate::oidc::OidcConfig`] is not rendered here at all.
#[utoipa::path(
    get,
    path = "/api/v1/auth/config",
    description = "How to authenticate against this server: the auth mode (token-review, oidc, token-review-or-oidc, ...), plus the OIDC issuer, public client id and scopes when OIDC is enabled. Public by design — a client needs it before it has a credential.",
    tag = "auth",
    responses((status = 200, description = "The authentication configuration", body = AuthConfigView)),
)]
pub async fn auth_config(State(state): State<AppState>) -> Json<AuthConfigView> {
    // Finding `N4a`: `authMode` is a promise. Publishing `oidc` with no issuer and no client id
    // tells every Web UI and CLI to start a sign-in flow that cannot complete, so an `AppState`
    // built as `with_auth(AuthPolicy::Oidc)` without the matching `with_auth_config` is a builder
    // bug. The binary cannot produce it (`--oidc-issuer`/`--oidc-client-id` are required and the
    // server refuses to start), so this is asserted in debug builds only — where a test or an
    // embedder's own suite runs — and is a no-op in a release binary that never reaches it.
    debug_assert!(
        state.auth_config_matches_policy(),
        "with_auth(AuthPolicy::{}) must be paired with with_auth_config(PublicAuthConfig::oidc(..)): \
         GET /api/v1/auth/config would publish an OIDC sign-in mode with no issuer and no client id",
        state.auth.as_str()
    );
    Json(AuthConfigView {
        auth_mode: state.auth.as_str().to_owned(),
        issuer: state.auth_config.issuer.clone(),
        client_id: state.auth_config.client_id.clone(),
        scopes: state.auth_config.scopes.clone(),
        bff_enabled: state.auth_config.bff_enabled,
    })
}

// ---------------------------------------------------------------------------
// Handlers: applications
// ---------------------------------------------------------------------------

/// Lists every `Application` this control plane watches, filtered to the caller's projects.
///
/// **The filter is the authorization** (`T14.4` trap guard): an application in a project the caller
/// has no grant on is simply absent — the same answer a control plane that does not manage it would
/// give — so a tenant cannot learn about another tenant's applications by listing them, and the
/// response never reports how many were filtered out.
///
/// # Errors
///
/// [`ApiError::Backend`] when the cluster cannot be listed.
#[utoipa::path(
    get,
    path = "/api/v1/applications",
    description = "Every `Application` this control plane watches, with its sync/health verdict. Filtered to the projects the caller is authorized for: anything outside them is absent, exactly as if it did not exist.",
    tag = "applications",
    responses(
        (status = 200, description = "Every watched Application the caller may see", body = ApplicationListView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 502, description = "The cluster could not be read", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_applications(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<ApplicationListView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let applications = state.applications.list().await?;
    Ok(Json(ApplicationListView {
        items: applications
            .iter()
            .filter(|app| actor.can_see(&app.spec.project))
            .map(application_summary)
            .collect(),
    }))
}

/// Reads one `Application`.
///
/// # Errors
///
/// [`ApiError::NotFound`] when it does not exist (or lives outside the watched namespaces) **and**
/// when the caller has no grant on its project: the two answers are byte-identical, so a `404` can
/// never be used to discover that an application exists (trap guard).
/// [`ApiError::Forbidden`] only when the caller can already see the application but lacks `get`.
#[utoipa::path(
    get,
    path = "/api/v1/applications/{namespace}/{name}",
    description = "One `Application`, with its conditions, deployment history, and running operation. An application in a project the caller may not see answers exactly the 404 a nonexistent one answers.",
    tag = "applications",
    params(
        ("namespace" = String, Path, description = "Namespace of the Application"),
        ("name" = String, Path, description = "Name of the Application"),
    ),
    responses(
        (status = 200, description = "The Application", body = ApplicationDetailView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 403, description = "The caller may see this Application but not read it", body = ApiErrorBody),
        (status = 404, description = "No such Application, or none visible to the caller", body = ApiErrorBody),
        (status = 502, description = "The cluster could not be read", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_application(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request_id: Option<Extension<RequestId>>,
    fingerprint: Option<Extension<TokenFingerprint>>,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<ApplicationDetailView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let app = require_application(&state, &namespace, &name).await?;
    authorize(
        &state,
        &actor,
        &identity,
        request_id.as_ref().map(|Extension(id)| id.as_str()),
        fingerprint.as_ref().map(|Extension(fp)| fp),
        &app,
        &namespace,
        &name,
        Action::Get,
        "read",
    )?;
    // `T17.4`: the sync-window verdict the modal explains.
    //
    // Finding M4: the project is a *different* object from the `Application`, so the caller's grant
    // on the `Application` is not a grant on the project's `spec.syncWindows` — the verdict is only
    // derived from a project this actor may see, and is omitted (not guessed) otherwise. A project
    // that cannot be read is logged rather than silently answering "no windows", which would
    // tell every caller that their change freeze does not exist.
    //
    // Finding M-4: the project is resolved by name (`ProjectCatalog::get`), the one object this
    // page needs, instead of listing the whole catalogue per request. Every "not resolvable" answer
    // — absent, or invisible to this actor — still yields no verdict at all.
    let now = Timestamp::now();
    let project = match state.projects.get(&app.spec.project).await {
        Ok(project) => project,
        Err(err) => {
            tracing::warn!(
                error = %err,
                application = %format!("{namespace}/{name}"),
                project = %app.spec.project,
                "could not read the AppProject to compute the sync-window verdict; omitting it"
            );
            None
        }
    };
    let project = project.filter(|project| actor.can_see(&project.name_any()));
    Ok(Json(application_detail(&app, project.as_ref(), now)))
}

/// Reads the live resource graph of an `Application` (`T14.1`).
///
/// The inventory is read on demand from the destination cluster (never from an informer), and
/// `Deployment`/`StatefulSet`/`DaemonSet` children are discovered by one namespace-scoped
/// `metadata.ownerReferences` traversal per workload, one and two levels deep
/// (`Deployment -> ReplicaSet -> Pod`). The listed namespace is the resource's own, which scope
/// normalization pins to `spec.destination.namespace` unless the manifest sets one explicitly, so a
/// hardcoded namespace is traversed where the object actually lives. The response is capped at
/// [`MAX_GRAPH_NODES`].
///
/// # Exact cost of one request (finding `P14-H2`, `P14-M5`)
///
/// Let `I` be `len(status.inventory)` and `N` the number of traversable nodes reached:
///
/// * **`I` scoped live reads** — one per inventory key, the same read a reconcile performs
///   ([`crate::state::InventoryReader`], bounded concurrency inside the reader).
/// * **At most `min(N, MAX_GRAPH_LIST_REQUESTS)` listings**, and only **one per distinct
///   `(cluster, namespace, kind)`** for the whole request: the traversal caches them
///   ([`GraphTraversal`]), so twenty `Deployment`s in one namespace cost one `ReplicaSet` list, and
///   every `ReplicaSet` of that namespace costs one `Pod` list. Each listing is `ListParams::limit`ed
///   ([`crate::state::GRAPH_LIST_LIMIT`]) and owner references are matched in memory.
/// * **Zero writes**: nothing is applied, patched, or pruned.
///
/// The reads are sequential (one level finishes before the next begins), which is what keeps a
/// single request's concurrency at one cluster read at a time; the budget above is what bounds the
/// sequence. A request that reaches it answers `truncated: true` instead of continuing to walk.
///
/// # Errors
///
/// [`ApiError::NotFound`] for an unknown (or invisible) `Application`, [`ApiError::Forbidden`] when
/// the caller may see it but not read it, [`ApiError::Backend`] when the destination cluster cannot
/// be read.
#[utoipa::path(
    get,
    path = "/api/v1/applications/{namespace}/{name}/resources",
    description = "The live resource graph: `status.inventory` read on demand from the destination cluster, plus `Deployment -> ReplicaSet -> Pod` children discovered through `metadata.ownerReferences` (no informers). One listing per (cluster, namespace, kind) per request, bounded by `MAX_GRAPH_NODES` and `MAX_GRAPH_LIST_REQUESTS`.",
    tag = "applications",
    params(
        ("namespace" = String, Path, description = "Namespace of the Application"),
        ("name" = String, Path, description = "Name of the Application"),
    ),
    responses(
        (status = 200, description = "The live resource graph", body = ResourceGraphView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 403, description = "The caller may see this Application but not read it", body = ApiErrorBody),
        (status = 404, description = "No such Application, or none visible to the caller", body = ApiErrorBody),
        (status = 502, description = "The destination cluster could not be read", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_resources(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request_id: Option<Extension<RequestId>>,
    fingerprint: Option<Extension<TokenFingerprint>>,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<ResourceGraphView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let app = require_application(&state, &namespace, &name).await?;
    authorize(
        &state,
        &actor,
        &identity,
        request_id.as_ref().map(|Extension(id)| id.as_str()),
        fingerprint.as_ref().map(|Extension(fp)| fp),
        &app,
        &namespace,
        &name,
        Action::Get,
        "read",
    )?;
    let live = state.inventory.read(&app).await?;
    let status = app.status.clone().unwrap_or_default();
    let per_resource = resource_health(&status);

    // One traversal (and therefore one listing cache + one read budget) for this request.
    let traversal = GraphTraversal::new();
    let mut nodes: Vec<ResourceNodeView> = Vec::new();
    let mut truncated = false;
    for state_of in &live {
        if nodes.len() >= MAX_GRAPH_NODES {
            truncated = true;
            break;
        }
        let mut node = node_view(
            &state_of.key,
            state_of.present,
            state_of.ownership,
            &per_resource,
        );
        node.parent = None;
        let traversable = node.namespace.is_some()
            && (TRAVERSABLE_KINDS.contains(&node.kind.as_str())
                || SECOND_LEVEL_KINDS.contains(&node.kind.as_str()));
        nodes.push(node.clone());
        if !traversable || !state_of.present {
            continue;
        }
        // Two levels only, and only for the workload kinds that own pods. Every level is a bounded,
        // namespace-scoped `list`, cached per `(cluster, namespace, kind)` on `traversal`.
        let children = state
            .graph
            .children(
                &traversal,
                &GraphRequest {
                    cluster: &app.spec.destination.cluster,
                    namespace: node.namespace.as_deref().unwrap_or_default(),
                    kind: &node.kind,
                    name: &node.name,
                },
            )
            .await?;
        for child in children {
            if nodes.len() >= MAX_GRAPH_NODES {
                truncated = true;
                break;
            }
            let mut child_node = node_view(&child.key, true, None, &per_resource);
            child_node.parent = Some(node.key.clone());
            nodes.push(child_node.clone());
            if SECOND_LEVEL_KINDS.contains(&child_node.kind.as_str())
                && let Some(child_namespace) = child_node.namespace.clone()
            {
                let grandchildren = state
                    .graph
                    .children(
                        &traversal,
                        &GraphRequest {
                            cluster: &app.spec.destination.cluster,
                            namespace: &child_namespace,
                            kind: &child_node.kind,
                            name: &child_node.name,
                        },
                    )
                    .await?;
                for grandchild in grandchildren {
                    if nodes.len() >= MAX_GRAPH_NODES {
                        truncated = true;
                        break;
                    }
                    let mut grandchild_node = node_view(&grandchild.key, true, None, &per_resource);
                    grandchild_node.parent = Some(child_node.key.clone());
                    nodes.push(grandchild_node);
                }
            }
        }
    }
    if traversal.is_exhausted() {
        // The listing budget stopped the traversal: say so instead of returning a graph that looks
        // complete (the same field the node cap uses).
        tracing::warn!(
            app.namespace = %app.namespace().unwrap_or_default(),
            app.name = %app.name_any(),
            traversal = traversal.id(),
            listings = traversal.listings_issued(),
            budget = MAX_GRAPH_LIST_REQUESTS,
            "the resource graph stopped at the per-request listing budget"
        );
        truncated = true;
    }

    Ok(Json(ResourceGraphView {
        namespace: app.spec.destination.namespace.clone(),
        cluster: app.spec.destination.cluster.clone(),
        sync_status: status
            .sync
            .as_ref()
            .map_or_else(|| "Unknown".to_owned(), |sync| label(&sync.status)),
        health_status: status
            .health
            .as_ref()
            .map_or_else(|| "Unknown".to_owned(), |health| label(&health.status)),
        nodes,
        truncated,
    }))
}

/// Reads the Kubernetes `Event`s that regard an `Application` (`T17.3`).
///
/// This is the timeline an operator reads during an incident: `Normal`/`Warning` `events.k8s.io/v1`
/// events emitted by the controller for this `Application` (`SyncSucceeded`, `SyncFailed`,
/// `ResourcePruned`, ...), newest first, bounded to [`MAX_APPLICATION_EVENTS`].
///
/// # Scope (trap guard)
///
/// The read is *always* narrowed twice, in [`crate::state::EventSource`]'s implementation:
/// `Api::<Event>::namespaced(app.namespace)` and `field_selector("regarding.uid=<app uid>")`. There is
/// no namespace-wide and no cluster-wide fallback: an `Application` without a `metadata.uid` answers
/// an empty timeline rather than every event in its namespace, and Events about *other* Applications
/// (or other tenants' workloads in the same namespace) are never fetched at all.
///
/// # Redaction
///
/// Every `note` goes through `ferriscd_controller::events::sanitize_note` — the controller's own
/// redactor, which masks URL credentials and embedded secret payloads and caps the message at the
/// `events.k8s.io/v1` 1 KiB limit. An `Event` note can quote a repository URL or a failed apply, so
/// the redaction happens here, on the way out, for **every** source implementation.
///
/// # Errors
///
/// [`ApiError::NotFound`] when the `Application` does not exist **or** the caller has no grant on its
/// project (byte-identical answers), [`ApiError::Forbidden`] when it is visible but `get` is not
/// granted, [`ApiError::Backend`] when the cluster cannot be read.
#[utoipa::path(
    get,
    path = "/api/v1/applications/{namespace}/{name}/events",
    description = "The latest Kubernetes `events.k8s.io/v1` events about one `Application` (`Normal`/`Warning`), newest first and bounded to 50. Read strictly from the `Application`'s own namespace with a `regarding.uid` field selector (never cluster-wide), and every note is `Secret`/token redacted.",
    tag = "applications",
    params(
        ("namespace" = String, Path, description = "Namespace of the Application"),
        ("name" = String, Path, description = "Name of the Application"),
    ),
    responses(
        (status = 200, description = "The bounded, redacted events timeline", body = ApplicationEventListView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 403, description = "The caller may see this Application but not read it", body = ApiErrorBody),
        (status = 404, description = "No such Application, or none visible to the caller", body = ApiErrorBody),
        (status = 502, description = "The cluster could not be read", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_application_events(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request_id: Option<Extension<RequestId>>,
    fingerprint: Option<Extension<TokenFingerprint>>,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<ApplicationEventListView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let app = require_application(&state, &namespace, &name).await?;
    authorize(
        &state,
        &actor,
        &identity,
        request_id.as_ref().map(|Extension(id)| id.as_str()),
        fingerprint.as_ref().map(|Extension(fp)| fp),
        &app,
        &namespace,
        &name,
        Action::Get,
        "read",
    )?;
    let events = state.events.list(&app).await?;
    Ok(Json(event_list_view(events)))
}

/// The SSE dashboard feed (`T17.3`): `text/event-stream` of RBAC-filtered `Application` snapshots.
///
/// Each `applications` frame is the same `ApplicationListView` body `GET /api/v1/applications`
/// answers, re-read from the live RBAC store and filtered to the projects **this caller** may see
/// before it is written to the socket: a snapshot can therefore never carry another tenant's
/// application, and a policy change takes effect on the next frame without reconnecting.
///
/// # Authentication (trap guard)
///
/// The credentials come from the ordinary `Authorization: Bearer` header, exactly like every other
/// protected route: this route is authenticated by the shared middleware, and the handler reads no
/// token from the query string. That is deliberate — `EventSource` cannot set headers, which is why
/// the UI consumes this feed with `fetch()` streaming (and why a token must never be put in a URL,
/// where it would land in access logs, proxies and `Referer` headers).
///
/// # Termination and boundedness
///
/// The body is a stream over [`crate::state::ApplicationSnapshotSource::subscribe`], backed by one
/// shared refresher per feed: the watch channel keeps only the latest snapshot, so a slow client
/// skips intermediate frames instead of growing a queue. Dropping the response body (a client
/// disconnect) drops the subscription, and the refresher stops with the last receiver. A failing
/// snapshot ends the stream with one `error` frame (the standard `{"error":{"code","message"}}`
/// shape) so the client can fall back to polling.
#[utoipa::path(
    get,
    path = "/api/v1/applications/stream",
    description = "A `text/event-stream` feed of `Application` snapshots, each filtered to the projects the caller is authorized for (a snapshot never contains another tenant's application). Authenticated with the standard `Authorization: Bearer` header — never a query parameter, which is why the UI consumes it with `fetch()` streaming. A snapshot failure ends the stream with one `error` frame so the client can fall back to polling.",
    tag = "applications",
    responses(
        (status = 200, description = "A `text/event-stream` of RBAC-filtered `Application` snapshots (`event: applications`, one `ApplicationListView` JSON body per frame)"),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn stream_applications(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Response {
    let feed = sse_feed(state.snapshots.subscribe(), state.rbac.clone(), identity);
    Sse::new(feed)
        .keep_alive(KeepAlive::new().interval(SSE_KEEP_ALIVE).text("keep-alive"))
        .into_response()
}

/// The SSE event name of one application snapshot.
pub const SSE_EVENT_APPLICATIONS: &str = "applications";

/// The SSE event name of a terminal feed error.
pub const SSE_EVENT_ERROR: &str = "error";

/// How often an idle SSE connection sends a comment frame.
///
/// Corporate proxies routinely drop a connection with no bytes for 30–60 s; a 15 s keep-alive keeps
/// the connection alive without producing any RBAC-filtered payload.
pub const SSE_KEEP_ALIVE: Duration = Duration::from_secs(15);

/// One connection's SSE state machine.
struct SseFeedState {
    source: BoxStream<'static, Result<Vec<Application>, ApiError>>,
    rbac: RbacPolicyStore,
    identity: AuthenticatedIdentity,
    done: bool,
}

/// Maps a snapshot source into SSE frames, filtering **every** frame through the live RBAC policy.
///
/// Split out of the handler so a test can drive it frame by frame without an HTTP stack, and so the
/// two invariants live in one place: a snapshot is filtered before it is serialized, and a failure
/// ends the stream (instead of looping on the same error forever).
fn sse_feed(
    source: BoxStream<'static, Result<Vec<Application>, ApiError>>,
    rbac: RbacPolicyStore,
    identity: AuthenticatedIdentity,
) -> impl futures::Stream<Item = Result<SseEvent, Infallible>> {
    let state = SseFeedState {
        source,
        rbac,
        identity,
        done: false,
    };
    futures::stream::unfold(state, |mut state| async move {
        if state.done {
            return None;
        }
        let snapshot = state.source.next().await?;
        let event = match snapshot {
            Ok(applications) => {
                // The live store, re-read per frame: revoking a project takes effect on the next
                // snapshot instead of on the next reconnect.
                let policy = state.rbac.snapshot();
                let actor = Actor::new(&policy, &state.identity);
                let items: Vec<ApplicationSummary> = applications
                    .iter()
                    .filter(|app| actor.can_see(&app.spec.project))
                    .map(application_summary)
                    .collect();
                match SseEvent::default()
                    .event(SSE_EVENT_APPLICATIONS)
                    .json_data(ApplicationListView { items })
                {
                    Ok(event) => event,
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "an application snapshot could not be serialized for the SSE feed"
                        );
                        state.done = true;
                        error_frame(&ApiError::backend(&error))
                    }
                }
            }
            Err(error) => {
                // One terminal frame, then the stream ends: the client reconnects (or falls back to
                // polling) instead of receiving the same failure as an infinite loop.
                tracing::warn!(
                    code = error.code(),
                    "the application snapshot feed failed; ending the SSE stream"
                );
                state.done = true;
                error_frame(&error)
            }
        };
        Some((Ok(event), state))
    })
}

/// One terminal `error` frame carrying the standard `{"error":{...}}` body.
fn error_frame(error: &ApiError) -> SseEvent {
    let body = ApiErrorBody::from(error.clone());
    SseEvent::default()
        .event(SSE_EVENT_ERROR)
        .json_data(body)
        .unwrap_or_else(|_| {
            // A DTO that carries two `String`s cannot fail to serialize; this keeps the handler
            // total (no `unwrap`) even if that ever changes.
            SseEvent::default()
                .event(SSE_EVENT_ERROR)
                .data(r#"{"error":{"code":"BackendUnavailable","message":"the stream failed"}}"#)
        })
}

/// Maps an `EventSource` answer onto the wire body: bounded, newest first, every note redacted.
fn event_list_view(events: Vec<ApplicationEvent>) -> ApplicationEventListView {
    let truncated = events.len() > MAX_APPLICATION_EVENTS;
    ApplicationEventListView {
        items: events
            .into_iter()
            .take(MAX_APPLICATION_EVENTS)
            .map(event_view)
            .collect(),
        truncated,
    }
}

/// One event, with its note through the controller's redactor.
fn event_view(event: ApplicationEvent) -> ApplicationEventView {
    ApplicationEventView {
        name: event.name,
        type_: event.event_type,
        reason: ferriscd_controller::events::sanitize_note(&event.reason),
        // The controller's own redactor (`T15.2`): URL credentials and embedded secret payloads are
        // masked, and the message is capped at the `events.k8s.io/v1` 1 KiB limit.
        message: ferriscd_controller::events::sanitize_note(&event.note),
        action: event
            .action
            .as_deref()
            .map(ferriscd_controller::events::sanitize_note),
        count: event.count,
        reporting_component: event
            .reporting_component
            .as_deref()
            .map(ferriscd_controller::events::sanitize_note),
        last_observed_at: event.last_observed_at,
        first_observed_at: event.first_observed_at,
    }
}

/// Computes the live, Secret-redacted diff of an `Application` (`T14.1`).
///
/// This runs the **controller's own** read-only pipeline prefix in-process (shared `RepoCache`,
/// renderer cache, `ClusterManager`, `DiscoveryCache`, SSA `dryRun=All`), so the payload cannot
/// disagree with the next reconcile — and cannot carry a `Secret` value, because every change comes
/// from the engine's only redacting constructor. Nothing is written: this is a `GET`.
///
/// # Errors
///
/// [`ApiError::NotFound`] for an unknown (or invisible) `Application`, [`ApiError::Forbidden`] when
/// the caller may see it but lacks `diff`, and [`ApiError::Backend`] with the same refusal a sync
/// would report (a denied `AppProject`, an unusable revision, an unreachable destination cluster, a
/// render failure).
#[utoipa::path(
    get,
    path = "/api/v1/applications/{namespace}/{name}/diff",
    description = "The live, `Secret`-redacted Server-Side-Apply dry-run diff. Computed by the controller's own pipeline in-process, and read-only: nothing is applied, pruned, or patched.",
    tag = "applications",
    params(
        ("namespace" = String, Path, description = "Namespace of the Application"),
        ("name" = String, Path, description = "Name of the Application"),
    ),
    responses(
        (status = 200, description = "The redacted live diff", body = DiffView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 403, description = "The caller may see this Application but not diff it", body = ApiErrorBody),
        (status = 404, description = "No such Application, or none visible to the caller", body = ApiErrorBody),
        (status = 502, description = "The diff could not be computed", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_diff(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request_id: Option<Extension<RequestId>>,
    fingerprint: Option<Extension<TokenFingerprint>>,
    Path((namespace, name)): Path<(String, String)>,
) -> Result<Json<DiffView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let app = require_application(&state, &namespace, &name).await?;
    authorize(
        &state,
        &actor,
        &identity,
        request_id.as_ref().map(|Extension(id)| id.as_str()),
        fingerprint.as_ref().map(|Extension(fp)| fp),
        &app,
        &namespace,
        &name,
        Action::Diff,
        "diff",
    )?;
    let preview = state.diffs.diff(&app).await?;
    Ok(Json(DiffView {
        revision: preview.revision,
        desired: preview.desired,
        would_sync: preview.would_sync,
        summary: DiffSummaryView {
            total: preview.summary.total,
            synced: preview.summary.synced,
            out_of_sync: preview.summary.out_of_sync,
            missing: preview.summary.missing,
            orphaned: preview.summary.orphaned,
            ownership_conflicts: preview.summary.ownership_conflicts,
            field_conflicts: preview.summary.field_conflicts,
        },
        resources: preview.diffs.iter().map(diff_resource_view).collect(),
    }))
}

/// Requests a manual sync (`T14.1`).
///
/// The API does **not** sync anything: it patches `ferriscd.io/operation` to `{"sync":{}}`, which the
/// composite watch predicate turns into a reconcile and the sync decision gate honours as a manual
/// operation. Responds `202 Accepted` — "the controller will act on this" — never `200`.
///
/// # The annotation is consumed (finding `P14-C1`)
///
/// A manual sync is a **one-shot** request: once a pass has settled, the controller clears
/// `{"sync":{}}` itself, because `manual_operation()` reads that annotation and leaving it behind
/// would keep bypassing `automated: None` forever. The API therefore has to handle a *pending*
/// request without pretending it is a conflict:
///
/// * **nothing pending** → the annotation is written, `202`;
/// * **a manual sync pending** → `202` again, **idempotent**: the response reports the value that is
///   already recorded and nothing is written (asking for a sync while one is waiting is not an
///   error, and a client that retries must not be told its own retry failed);
/// * **a rollback pending** → `409`: the rollback is an explicit operator request for a *specific*
///   commit and the annotation has a single slot, so a sync must not silently cancel it. This is
///   transient — the controller consumes the rollback as soon as it applies it — never permanent.
///
/// # Errors
///
/// * `409` when a rollback is pending and has not been consumed yet, or when the object changed
///   between the read and the patch (the compare-and-swap precondition failed).
/// * `413` for a body over the router's limit, `400` for a body that is not JSON.
/// * `422` for a body asking for something `v1.0` cannot honour (`revision`, `prune`, `dryRun`):
///   silently ignoring it would report a sync that did not happen the way it was requested.
/// * `404` when the `Application` does not exist **or** the caller has no grant on its project
///   (identical answers), `403` when it is visible but `sync` is not granted (`T14.4`).
#[utoipa::path(
    post,
    path = "/api/v1/applications/{namespace}/{name}/sync",
    description = "Requests a reconcile by patching `ferriscd.io/operation` to `{\"sync\":{}}`. The controller does the work; this endpoint never syncs anything itself, and the controller consumes the annotation once a pass has settled. A pending manual sync answers 202 (idempotent); only a pending rollback is a conflict.",
    tag = "applications",
    params(
        ("namespace" = String, Path, description = "Namespace of the Application"),
        ("name" = String, Path, description = "Name of the Application"),
    ),
    request_body = inline(SyncRequestBody),
    responses(
        (status = 202, description = "The sync request was recorded (or is already pending)", body = OperationResponse),
        (status = 400, description = "The body is not JSON", body = ApiErrorBody),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 403, description = "The caller may see this Application but not sync it", body = ApiErrorBody),
        (status = 404, description = "No such Application, or none visible to the caller", body = ApiErrorBody),
        (status = 409, description = "A rollback is pending, or the Application changed", body = ApiErrorBody),
        (status = 413, description = "Payload too large", body = ApiErrorBody),
        (status = 422, description = "The request cannot be honoured", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn sync_application(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request_id: Option<Extension<RequestId>>,
    fingerprint: Option<Extension<TokenFingerprint>>,
    Path((namespace, name)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<OperationResponse>), ApiError> {
    // An absent body and `{}` both mean "plain reconcile": nothing in `SyncRequestBody` is required.
    if let Some(request) =
        parse_optional_body::<SyncRequestBody>(state.webhooks.max_body_bytes(), body)?
    {
        let unsupported: Vec<&str> = [
            request.revision.as_ref().map(|_| "revision"),
            request.prune.filter(|prune| *prune).map(|_| "prune"),
            request.dry_run.filter(|dry_run| *dry_run).map(|_| "dryRun"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !unsupported.is_empty() {
            return Err(ApiError::unprocessable(format!(
                "this server cannot honour {} yet: `POST .../sync` requests a plain reconcile \
                 (pin a revision with a rollback, prune from spec.syncPolicy.automated.prune, and \
                 use `GET .../diff` to preview)",
                unsupported.join(", ")
            )));
        }
    }
    let req_id = request_id.as_ref().map(|Extension(id)| id.as_str());
    let fp = fingerprint.as_ref().map(|Extension(fp)| fp);
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let app = require_application(&state, &namespace, &name).await?;
    authorize(
        &state,
        &actor,
        &identity,
        req_id,
        fp,
        &app,
        &namespace,
        &name,
        Action::Sync,
        "sync",
    )?;
    let operation = OperationRequest::Sync;
    request_operation(&state, &identity, req_id, fp, &app, operation).await
}

/// Requests a rollback to a history entry (`T14.1`).
///
/// The `Application` must already have `status.history` (a rollback of something never deployed is
/// not a rollback). The API patches `{"rollback":{"id":N}}`; the controller pins the commit, disables
/// `spec.syncPolicy.automated` and records a `Warning` condition, exactly as for an annotation
/// written by hand. It then **consumes** the annotation, so the request cannot re-trigger forever.
///
/// A rollback **supersedes** whatever is in the single `ferriscd.io/operation` slot — a pending
/// manual sync, or an earlier rollback that has not been picked up yet. The operator asked for a
/// specific commit most recently, and the annotation cannot carry two requests (finding `P14-C1`).
///
/// # Errors
///
/// * `404` for an unknown `Application`.
/// * `409` when the object changed under the request (the compare-and-swap precondition failed).
/// * `413` for a body over the router's limit, `400` for a body that is not the expected JSON.
/// * `422` when `status.history` has no entry with that id.
/// * `404` when the `Application` does not exist **or** the caller has no grant on its project
///   (identical answers), `403` when it is visible but `rollback` is not granted (`T14.4`).
#[utoipa::path(
    post,
    path = "/api/v1/applications/{namespace}/{name}/rollback",
    description = "Requests a rollback by patching `ferriscd.io/operation` to `{\"rollback\":{\"id\":N}}`. The id must exist in `status.history`. A rollback supersedes a pending manual sync or an earlier rollback (one annotation slot) and is consumed by the controller once applied.",
    tag = "applications",
    params(
        ("namespace" = String, Path, description = "Namespace of the Application"),
        ("name" = String, Path, description = "Name of the Application"),
    ),
    request_body = RollbackRequestBody,
    responses(
        (status = 202, description = "The rollback request was recorded", body = OperationResponse),
        (status = 400, description = "The body is not the expected JSON", body = ApiErrorBody),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 403, description = "The caller may see this Application but not roll it back", body = ApiErrorBody),
        (status = 404, description = "No such Application, or none visible to the caller", body = ApiErrorBody),
        (status = 409, description = "The Application changed while the request was recorded", body = ApiErrorBody),
        (status = 413, description = "Payload too large", body = ApiErrorBody),
        (status = 422, description = "No history entry with that id", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn rollback_application(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
    request_id: Option<Extension<RequestId>>,
    fingerprint: Option<Extension<TokenFingerprint>>,
    Path((namespace, name)): Path<(String, String)>,
    body: Result<Bytes, BytesRejection>,
) -> Result<(StatusCode, Json<OperationResponse>), ApiError> {
    let body = require_body(state.webhooks.max_body_bytes(), body)?;
    let request: RollbackRequestBody = parse_body(&body)?;
    let req_id = request_id.as_ref().map(|Extension(id)| id.as_str());
    let fp = fingerprint.as_ref().map(|Extension(fp)| fp);
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let app = require_application(&state, &namespace, &name).await?;
    authorize(
        &state,
        &actor,
        &identity,
        req_id,
        fp,
        &app,
        &namespace,
        &name,
        Action::Rollback,
        "roll back",
    )?;
    let history: &[RevisionHistoryEntry] = app
        .status
        .as_ref()
        .map_or(&[], |status| status.history.as_slice());
    if !history.iter().any(|entry| entry.id == request.id) {
        let known: Vec<i64> = history.iter().map(|entry| entry.id).collect();
        record_api_operation(
            &state.audit,
            req_id,
            &identity,
            fp,
            &app,
            "rollback",
            AuditOutcome::Failed,
            Some(&format!(
                "requested history id {} not found in status.history",
                request.id
            )),
        );
        return Err(ApiError::unprocessable(format!(
            "status.history has no entry with id {}; known ids: {known:?}",
            request.id
        )));
    }
    request_operation(
        &state,
        &identity,
        req_id,
        fp,
        &app,
        OperationRequest::Rollback { id: request.id },
    )
    .await
}

/// Patches `ferriscd.io/operation` according to the single annotation slot.
async fn request_operation(
    state: &AppState,
    identity: &AuthenticatedIdentity,
    request_id: Option<&str>,
    fingerprint: Option<&TokenFingerprint>,
    app: &Application,
    operation: OperationRequest,
) -> Result<(StatusCode, Json<OperationResponse>), ApiError> {
    let namespace = app.namespace().ok_or_else(|| {
        ApiError::unprocessable(
            "the Application has no metadata.namespace, so no operation can be recorded on it",
        )
    })?;
    let name = app.name_any();
    let resource_version = app.metadata.resource_version.clone();
    match (pending_operation(app), operation) {
        // Idempotent: the controller has not consumed the manual sync yet, and a second request is
        // the same request. Writing again would only churn `resourceVersion`.
        (PendingOperation::ManualSync(value), OperationRequest::Sync) => {
            record_api_operation(
                &state.audit,
                request_id,
                identity,
                fingerprint,
                app,
                operation.label(),
                AuditOutcome::Accepted,
                Some("manual sync already pending (idempotent)"),
            );
            tracing::info!(
                app.namespace = %namespace,
                app.name = %name,
                operation = operation.label(),
                "manual sync already pending: reporting it instead of re-writing the annotation"
            );
            return Ok((
                StatusCode::ACCEPTED,
                Json(OperationResponse {
                    status: "accepted".to_owned(),
                    operation: operation.label().to_owned(),
                    namespace,
                    name,
                    request: value,
                    resource_version,
                }),
            ));
        }
        // The single slot cannot carry both, and silently cancelling an explicit rollback would
        // redeploy the wrong commit. Transient: the controller consumes a rollback once applied.
        (PendingOperation::Rollback(value), OperationRequest::Sync) => {
            record_api_operation(
                &state.audit,
                request_id,
                identity,
                fingerprint,
                app,
                operation.label(),
                AuditOutcome::Failed,
                Some("conflict: rollback operation already pending"),
            );
            return Err(ApiError::conflict(format!(
                "a rollback is pending on {namespace}/{name} ({} = {value:?}) and has not been \
                 applied yet; it replaces the manual sync this request asks for, so remove the \
                 annotation or wait for the controller to consume it",
                annotations_operation()
            )));
        }
        // Nothing pending, or a request that supersedes what is there (a rollback always does).
        (
            PendingOperation::None
            | PendingOperation::ManualSync(_)
            | PendingOperation::Rollback(_),
            _,
        ) => {}
    }
    if let Err(error) = state
        .operations
        .request(&namespace, &name, resource_version.as_deref(), operation)
        .await
    {
        record_api_operation(
            &state.audit,
            request_id,
            identity,
            fingerprint,
            app,
            operation.label(),
            AuditOutcome::Failed,
            Some("failed to record operation annotation on Application"),
        );
        return Err(error);
    }
    let audit_reason = match operation {
        OperationRequest::Sync => "manual sync operation recorded".to_owned(),
        OperationRequest::Rollback { id } => {
            format!("rollback operation recorded for history id {id}")
        }
    };
    record_api_operation(
        &state.audit,
        request_id,
        identity,
        fingerprint,
        app,
        operation.label(),
        AuditOutcome::Accepted,
        Some(&audit_reason),
    );
    tracing::info!(
        app.namespace = %namespace,
        app.name = %name,
        operation = operation.label(),
        "manual operation requested through the API"
    );
    Ok((
        StatusCode::ACCEPTED,
        Json(OperationResponse {
            status: "accepted".to_owned(),
            operation: operation.label().to_owned(),
            namespace,
            name,
            request: operation.annotation_value(),
            resource_version,
        }),
    ))
}

/// `ferriscd.io/operation`, for messages (never inlined by hand).
fn annotations_operation() -> &'static str {
    annotations::OPERATION
}

/// What is currently recorded in the `ferriscd.io/operation` slot.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingOperation {
    /// Nothing is recorded (no annotation, or a blank one).
    None,
    /// A manual sync request — any non-blank value that is not a rollback, exactly as the
    /// controller's `manual_operation()` reads it.
    ManualSync(String),
    /// A `{"rollback":{"id":N}}` request the controller has not consumed yet.
    Rollback(String),
}

/// The pending `ferriscd.io/operation` request, if any.
fn pending_operation(app: &Application) -> PendingOperation {
    let Some(value) = app
        .annotations()
        .get(annotations::OPERATION)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return PendingOperation::None;
    };
    match ferriscd_engine::sync::parse_rollback_request(value) {
        Ok(_) => PendingOperation::Rollback(value.to_owned()),
        // `NotARollback` is the documented manual sync; an unparseable value is a broken request the
        // controller refuses, and a new one must be able to replace it rather than be refused twice.
        Err(_) => PendingOperation::ManualSync(value.to_owned()),
    }
}

/// A required JSON body, with the crate's error shape instead of axum's (`P14-M1`).
///
/// # Errors
///
/// [`ApiError::PayloadTooLarge`] for a body over `limit`, [`ApiError::BadRequest`] when the body was
/// truncated or never arrived.
fn require_body(limit: usize, body: Result<Bytes, BytesRejection>) -> Result<Bytes, ApiError> {
    let body = reject_body(limit, body)?;
    if body.is_empty() {
        return Err(ApiError::bad_request(
            "the request has no body: a JSON object is required",
        ));
    }
    Ok(body)
}

/// An optional JSON body: an empty body means "the defaults" (`P14-M1`).
///
/// # Errors
///
/// See [`require_body`].
fn parse_optional_body<T: DeserializeOwned>(
    limit: usize,
    body: Result<Bytes, BytesRejection>,
) -> Result<Option<T>, ApiError> {
    let body = reject_body(limit, body)?;
    if body.is_empty() {
        return Ok(None);
    }
    parse_body(&body).map(Some)
}

/// Maps the body extractor's rejection onto the documented `{"error":…}` response.
///
/// An oversized body is the router's `DefaultBodyLimit`, which is the documented `413`; everything
/// else (a truncated or aborted body) is the caller's `400`. The rejection's own message is never
/// forwarded: it is axum's prose, not the contract's shape.
fn reject_body(limit: usize, body: Result<Bytes, BytesRejection>) -> Result<Bytes, ApiError> {
    body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge { limit }
        } else {
            ApiError::bad_request(
                "the request body could not be read (it was truncated or never completed)",
            )
        }
    })
}

/// Parses a JSON request body without echoing what was sent (`P14-M1`).
fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|err| {
        // `serde_json`'s message can quote the offending value, and a request body may carry
        // material an operator pasted in; only the position is forwarded.
        ApiError::bad_request(format!(
            "the request body is not the expected JSON object (invalid JSON at line {}, column {})",
            err.line(),
            err.column()
        ))
    })
}

/// Lists every `AppProject` of the control-plane namespace the caller may see.
///
/// Filtered like the application list (`T14.4`): a project the caller holds no grant on is absent,
/// so the project catalogue is not a directory of other tenants either.
///
/// # Errors
///
/// [`ApiError::Backend`] when the cluster cannot be read.
#[utoipa::path(
    get,
    path = "/api/v1/projects",
    description = "Every `AppProject` of the control-plane namespace, with its repository, namespace, destination, and ServiceAccount allow-lists.",
    tag = "platform",
    responses(
        (status = 200, description = "Every AppProject", body = ProjectListView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 502, description = "The cluster could not be read", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_projects(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<ProjectListView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let projects = state.projects.list().await?;
    // One clock for the whole response: every window in the list is evaluated at the same instant,
    // so `active`/`nextStart` cannot contradict each other between entries.
    let now = Timestamp::now();
    Ok(Json(ProjectListView {
        items: projects
            .iter()
            .filter(|project| actor.can_see(&project.name_any()))
            .map(|project| project_view(project, now))
            .collect(),
    }))
}

/// Lists `ApplicationSet` objects (`T19.3`).
///
/// Read-only: generation happens in the opt-in controller loop, never in an API request. A caller
/// sees an `ApplicationSet` only when at least one `AppProject` visible to them
/// (`actor.can_see(project)`) is the project its template targets.
///
/// # Errors
///
/// [`ApiError::Backend`] when the `ApplicationSet` catalog cannot be listed.
#[utoipa::path(
    get,
    path = "/api/v1/applicationsets",
    description = "Every `ApplicationSet` of the control-plane namespace whose template targets an `AppProject` the caller may see, with its generator kinds, deletion/prune policy, and generation count.",
    tag = "platform",
    responses(
        (status = 200, description = "Every visible ApplicationSet", body = ApplicationSetListView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 502, description = "The cluster could not be read", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_applicationsets(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<ApplicationSetListView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let applicationsets = state.applicationsets.list().await?;
    Ok(Json(ApplicationSetListView {
        items: applicationsets
            .iter()
            .filter(|appset| actor.can_see(&appset.spec.template.spec.project))
            .map(applicationset_view)
            .collect(),
    }))
}

/// Lists addressable clusters visible to the caller's authorized `AppProject`s (`T13.1`, `T17.1`).
///
/// An authenticated caller sees `in-cluster` or a registered remote cluster only when at least one
/// `AppProject` visible to them (`actor.can_see(project)`) allows that cluster in
/// `spec.destinations` (matching with [`ferriscd_engine::policy::wildcard_matches`]). Unrestricted
/// (`PassThrough`) callers see the full cluster registry.
///
/// # Errors
///
/// [`ApiError::Backend`] when the `AppProject` catalog cannot be listed.
#[utoipa::path(
    get,
    path = "/api/v1/clusters",
    description = "The cluster registry filtered to clusters permitted by the caller's visible `AppProject`s: `in-cluster` first, then matching registered cluster names.",
    tag = "platform",
    responses(
        (status = 200, description = "Project-visible clusters", body = ClusterListView),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 502, description = "The cluster could not be read", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_clusters(
    State(state): State<AppState>,
    Extension(identity): Extension<AuthenticatedIdentity>,
) -> Result<Json<ClusterListView>, ApiError> {
    let rbac = state.rbac.snapshot();
    let actor = Actor::new(&rbac, &identity);
    let all_clusters = state.clusters.list();
    if actor.is_unrestricted() {
        return Ok(Json(ClusterListView {
            items: all_clusters
                .into_iter()
                .map(|ClusterEntry { name, in_cluster }| ClusterView { name, in_cluster })
                .collect(),
        }));
    }
    let projects = state.projects.list().await?;
    let visible_destinations: Vec<&str> = projects
        .iter()
        .filter(|project| actor.can_see(&project.name_any()))
        .flat_map(|project| {
            project
                .spec
                .destinations
                .iter()
                .map(|dest| dest.cluster.trim())
        })
        .collect();
    let items = all_clusters
        .into_iter()
        .filter(|entry| {
            visible_destinations
                .iter()
                .any(|pattern| ferriscd_engine::policy::wildcard_matches(pattern, &entry.name))
        })
        .map(|ClusterEntry { name, in_cluster }| ClusterView { name, in_cluster })
        .collect();
    Ok(Json(ClusterListView { items }))
}

/// Serves the OpenAPI 3.1 document (`T14.1`).
///
/// The same document is exported to `docs/api/openapi.json` by `ferriscd server openapi`, and the
/// TypeScript web UI is generated from it (`T16.1`), so the served and the committed contract are
/// one artifact (a test fails if they drift).
///
/// # Errors
///
/// [`ApiError::Backend`] if the document cannot be serialized. Answering `200 null` would hand the
/// UI an "empty but valid" contract instead (finding `P14-M3`).
#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    description = "This OpenAPI 3.1 document. The same bytes are committed to `docs/api/openapi.json` and used to generate the TypeScript client.",
    tag = "platform",
    responses(
        (status = 200, description = "The OpenAPI 3.1 document", body = Object),
        (status = 401, description = "Authentication required", body = ApiErrorBody),
        (status = 502, description = "The document could not be serialized", body = ApiErrorBody),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn openapi_document(
    _identity: Extension<AuthenticatedIdentity>,
) -> Result<Json<serde_json::Value>, ApiError> {
    openapi::document_value()
        .map(Json)
        .map_err(|err| ApiError::backend(&err))
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

/// Reads one `Application`, mapping absence to `404`.
async fn require_application(
    state: &AppState,
    namespace: &str,
    name: &str,
) -> Result<Application, ApiError> {
    state
        .applications
        .get(namespace, name)
        .await?
        .ok_or_else(|| ApiError::not_found("Application", namespace, name))
}

/// The `T14.4` gate for one `Application`, applied **before** any work is done for it.
///
/// One rule, in one place, so every handler answers consistently:
///
/// * **no grant at all** on the application's project → the *identical* `404` body a nonexistent
///   application gets. A caller who cannot see an application must not be able to tell it apart from
///   one that does not exist, whichever endpoint they probe (trap guard).
/// * **a grant, but not this action** → `403`. This is not an existence leak: the caller can already
///   read the application (or the list that contains it), so they already know it exists.
/// * otherwise → proceed.
///
/// `namespace`/`name` are the ones from the request path, not from the object, so the hidden `404` is
/// byte-identical to [`ApiError::not_found`]'s answer for a missing object.
#[allow(clippy::too_many_arguments)]
fn authorize(
    state: &AppState,
    actor: &Actor<'_>,
    identity: &AuthenticatedIdentity,
    request_id: Option<&str>,
    fingerprint: Option<&TokenFingerprint>,
    app: &Application,
    namespace: &str,
    name: &str,
    action: Action,
    verb: &'static str,
) -> Result<(), ApiError> {
    let grant = actor.grant(&app.spec.project);
    if !grant.is_visible() {
        record_rbac_denied(
            &state.audit,
            request_id,
            identity,
            fingerprint,
            app,
            action,
            StatusCode::NOT_FOUND,
        );
        return Err(ApiError::not_found("Application", namespace, name));
    }
    if grant.allows(action) {
        return Ok(());
    }
    record_rbac_denied(
        &state.audit,
        request_id,
        identity,
        fingerprint,
        app,
        action,
        StatusCode::FORBIDDEN,
    );
    Err(ApiError::Forbidden {
        message: format!(
            "not permitted to {verb} Application {namespace}/{name}: this identity has no `{}` \
             grant on AppProject {project}",
            action.as_str(),
            project = app.spec.project,
        ),
    })
}

/// Maps an `ApplicationSet` to its read-view representation.
fn applicationset_view(appset: &ferriscd_crd::ApplicationSet) -> ApplicationSetView {
    let status = appset.status.as_ref();
    let (generator, matrix) = appset
        .spec
        .generators
        .first()
        .map(generator_labels)
        .unwrap_or_else(|| ("unknown".to_owned(), Vec::new()));
    ApplicationSetView {
        namespace: appset.namespace().unwrap_or_default(),
        name: appset.name_any(),
        generator,
        matrix,
        project: appset.spec.template.spec.project.clone(),
        preserve_resources_on_deletion: appset.spec.sync_policy.preserve_resources_on_deletion,
        prune: appset.spec.sync_policy.prune,
        generated_count: status.map_or(0, |status| status.generated_count),
        conditions: status
            .map(|status| status.conditions.iter().map(condition_view).collect())
            .unwrap_or_default(),
        observed_generation: status.and_then(|status| status.observed_generation),
        ready: status
            .and_then(|status| {
                status
                    .conditions
                    .iter()
                    .find(|condition| condition.type_ == ferriscd_crd::status::CONDITION_READY)
            })
            .map(|condition| {
                match condition.status {
                    ConditionStatus::True => "True",
                    ConditionStatus::False => "False",
                    ConditionStatus::Unknown => "Unknown",
                }
                .to_owned()
            }),
    }
}

/// The generator kind labels of one `ApplicationSet` generator (and, for a matrix, its children).
fn generator_labels(generator: &ferriscd_crd::ApplicationSetGenerator) -> (String, Vec<String>) {
    use ferriscd_crd::ApplicationSetGenerator as Generator;
    match generator {
        Generator::List(_) => ("list".to_owned(), Vec::new()),
        Generator::Git(_) => ("git".to_owned(), Vec::new()),
        Generator::Clusters(_) => ("clusters".to_owned(), Vec::new()),
        Generator::Matrix(matrix) => (
            "matrix".to_owned(),
            matrix
                .generators
                .iter()
                .map(|child| child_generator_label(child).to_owned())
                .collect(),
        ),
    }
}

/// The kind label of one matrix child (the child type has no `matrix` variant by construction).
fn child_generator_label(generator: &ferriscd_crd::MatrixChildGenerator) -> &'static str {
    use ferriscd_crd::MatrixChildGenerator as Child;
    match generator {
        Child::List(_) => "list",
        Child::Git(_) => "git",
        Child::Clusters(_) => "clusters",
    }
}

/// Maps an `Application` to its list representation.
fn application_summary(app: &Application) -> ApplicationSummary {
    let status = app.status.as_ref();
    ApplicationSummary {
        namespace: app.namespace().unwrap_or_default(),
        name: app.name_any(),
        project: app.spec.project.clone(),
        source: SourceView {
            // `T18.4`: an OCI source reports `oci`, and its tag/digest, through the same view — the
            // URL goes through the same redaction rule either way.
            source_type: if app.spec.source.oci.is_some() {
                "oci".to_owned()
            } else {
                "git".to_owned()
            },
            // A Git remote routinely carries a personal access token (`https://oauth2:ghp_...@...`);
            // the same rule covers an `oci://` reference.
            repo_url: ferriscd_engine::manifest::redact_repo_url(app.spec.source.repo_url()),
            path: app.spec.source.source_path().to_owned(),
            target_revision: app.spec.source.requested_revision().to_owned(),
            tag: app.spec.source.oci.as_ref().and_then(|oci| oci.tag.clone()),
            digest: app
                .spec
                .source
                .oci
                .as_ref()
                .and_then(|oci| oci.digest.clone()),
            renderer: renderer_label(&app.spec.source.renderer).to_owned(),
        },
        destination: DestinationView {
            cluster: app.spec.destination.cluster.clone(),
            namespace: app.spec.destination.namespace.clone(),
        },
        sync: status
            .and_then(|status| status.sync.as_ref())
            .map(|sync| SyncView {
                status: label(&sync.status),
                revision: sync.revision.clone(),
                last_synced_revision: sync.last_synced_revision.clone(),
                last_synced_at: sync.last_synced_at.as_ref().and_then(time_string),
            }),
        health: status
            .and_then(|status| status.health.as_ref())
            .map(health_view),
        conditions: status
            .map(|status| status.conditions.iter().map(condition_view).collect())
            .unwrap_or_default(),
        resource_count: status.map_or(0, |status| status.inventory.len()),
        observed_generation: status.and_then(|status| status.observed_generation),
        applicationset: app
            .labels()
            .get(ferriscd_crd::APPLICATIONSET_LABEL)
            .cloned(),
    }
}

/// Maps an `Application` to its detail representation.
fn application_detail(
    app: &Application,
    project: Option<&AppProject>,
    now: Timestamp,
) -> ApplicationDetailView {
    let status = app.status.as_ref();
    ApplicationDetailView {
        application: application_summary(app),
        history: status
            .map(|status| status.history.iter().map(history_view).collect())
            .unwrap_or_default(),
        operation: status
            .and_then(|status| status.operation_state.as_ref())
            .map(operation_view),
        sync_window: sync_window_gate_view(project, app, now),
    }
}

fn health_view(health: &HealthState) -> HealthView {
    HealthView {
        status: label(&health.status),
        message: health.message.clone(),
    }
}

fn condition_view(condition: &ferriscd_crd::status::Condition) -> ConditionView {
    ConditionView {
        type_: condition.type_.clone(),
        status: match condition.status {
            ConditionStatus::True => "True",
            ConditionStatus::False => "False",
            ConditionStatus::Unknown => "Unknown",
        }
        .to_owned(),
        reason: condition.reason.clone(),
        message: condition.message.clone(),
        last_transition_time: time_string(&condition.last_transition_time).unwrap_or_default(),
        observed_generation: condition.observed_generation,
    }
}

fn history_view(entry: &RevisionHistoryEntry) -> HistoryView {
    HistoryView {
        id: entry.id,
        revision: entry.revision.clone(),
        deployed_at: time_string(&entry.deployed_at).unwrap_or_default(),
    }
}

fn operation_view(state: &ferriscd_crd::status::OperationState) -> OperationView {
    OperationView {
        phase: match state.phase {
            OperationPhase::Running => "Running",
            OperationPhase::Succeeded => "Succeeded",
            OperationPhase::Failed => "Failed",
            OperationPhase::Error => "Error",
        }
        .to_owned(),
        current_wave: state.current_wave,
        revision: state.revision.clone(),
        started_at: time_string(&state.started_at).unwrap_or_default(),
        finished_at: state.finished_at.as_ref().and_then(time_string),
        message: state.message.clone(),
    }
}

fn project_view(project: &AppProject, now: Timestamp) -> ProjectView {
    let windows = windows_view(project, now);
    ProjectView {
        name: project.name_any(),
        description: project.spec.description.clone(),
        source_repos: project.spec.source_repos.clone(),
        source_namespaces: project.spec.source_namespaces.clone(),
        destinations: project
            .spec
            .destinations
            .iter()
            .map(|destination| format!("{}/{}", destination.cluster, destination.namespace))
            .collect(),
        allowed_service_accounts: project.spec.allowed_service_accounts.clone(),
        sync_windows: windows.items,
        next_sync_window_transition: windows.next_transition,
    }
}

/// Rendering of `spec.syncWindows` for the API, with the state each window is in at `now`.
struct WindowsView {
    items: Vec<ProjectSyncWindowView>,
    next_transition: Option<String>,
}

/// Builds the window list in `spec` order, with unparseable entries marked instead of dropped.
///
/// The evaluation is the engine's ([`ferriscd_engine::policy::SyncWindowSet`]), never a second
/// implementation: `GET /api/v1/projects` and the controller's gate must agree about whether a
/// window is open.
fn windows_view(project: &AppProject, now: Timestamp) -> WindowsView {
    let spec = &project.spec;
    if spec.sync_windows.is_empty() {
        return WindowsView {
            items: Vec::new(),
            next_transition: None,
        };
    }
    let set = SyncWindowSet::from_spec(spec);
    let statuses = set.statuses(now);
    let items = spec
        .sync_windows
        .iter()
        .enumerate()
        .map(|(index, window)| {
            let status = statuses.iter().find(|status| status.index == index);
            ProjectSyncWindowView {
                kind: window.kind.as_str().to_owned(),
                schedule: status.map_or_else(
                    || window.schedule.trim().to_owned(),
                    |status| status.schedule.clone(),
                ),
                duration: window.duration.trim().to_owned(),
                time_zone: window.time_zone_name().to_owned(),
                applications: window.applications.clone(),
                namespaces: window.namespaces.clone(),
                clusters: window.clusters.clone(),
                manual_sync: window.manual_sync,
                active: status.is_some_and(|status| status.active),
                starts_at: status
                    .and_then(|status| status.starts_at)
                    .map(|instant| instant.to_string()),
                ends_at: status
                    .and_then(|status| status.ends_at)
                    .map(|instant| instant.to_string()),
                next_start: status
                    .and_then(|status| status.next_start)
                    .map(|instant| instant.to_string()),
                error: set
                    .invalid()
                    .iter()
                    .find(|invalid| invalid.index == index)
                    .map(|invalid| invalid.message.clone()),
            }
        })
        .collect();
    let next_transition = statuses
        .iter()
        .flat_map(|status| [status.ends_at, status.next_start])
        .flatten()
        .filter(|instant| *instant > now)
        .min()
        .map(|instant| instant.to_string());
    WindowsView {
        items,
        next_transition,
    }
}

/// The `T17.4` verdict for one `Application`, from its project's windows.
///
/// `None` when the project has no windows (nothing to explain) or is not in the catalogue (the
/// reconcile path already reports a missing project as a terminal policy denial — inventing a
/// window verdict for it here would be a second, quieter answer).
fn sync_window_gate_view(
    project: Option<&AppProject>,
    app: &Application,
    now: Timestamp,
) -> Option<SyncWindowGateView> {
    let project = project?;
    if !project.spec.has_sync_windows() {
        return None;
    }
    let set = SyncWindowSet::from_spec(&project.spec);
    let namespace = app.namespace().unwrap_or_default();
    let name = app.name_any();
    let target = SyncWindowTarget::new(&name, &namespace, &app.spec.destination.cluster);
    // A `Manual` trigger is what the modal asks about: `POST .../sync` is always manual, so the
    // view answers "would *my* click be honoured?".
    let verdict = set.evaluate(now, &target);
    Some(SyncWindowGateView {
        blocked: verdict.is_denied(),
        reason: verdict
            .denial()
            .map(|denial| denial.reason.as_str().to_owned()),
        message: verdict.message(now),
        manual_override: verdict.manual_override(),
        next_transition: verdict.next_transition().map(|instant| instant.to_string()),
    })
}

/// Per-resource health recorded by the last reconcile, keyed by GKNN.
fn resource_health(status: &ApplicationStatus) -> BTreeMap<String, (String, String)> {
    status
        .resources
        .iter()
        .map(|resource| {
            (
                resource.key.clone(),
                (label(&resource.health), resource.message.clone()),
            )
        })
        .collect()
}

fn node_view(
    key: &ResourceKey,
    present: bool,
    ownership: Option<&'static str>,
    health: &BTreeMap<String, (String, String)>,
) -> ResourceNodeView {
    let canonical = key.canonical();
    let recorded = health.get(&canonical);
    ResourceNodeView {
        key: canonical,
        group: key.group.clone(),
        kind: key.kind.clone(),
        namespace: key.namespace.clone(),
        name: key.name.clone(),
        present,
        ownership: ownership.map(ToOwned::to_owned),
        health: recorded.map(|(status, _)| status.clone()),
        health_message: recorded
            .map(|(_, message)| message.clone())
            .filter(|message| !message.is_empty()),
        parent: None,
    }
}

fn diff_resource_view(diff: &ResourceDiff) -> DiffResourceView {
    DiffResourceView {
        key: diff.key().canonical(),
        status: diff_status_label(diff.status()).to_owned(),
        owner: diff.status().foreign_owner().map(ToOwned::to_owned),
        changes: diff
            .changes()
            .iter()
            .map(|change| DiffChangeView {
                path: change.path.clone(),
                kind: change.kind.as_str().to_owned(),
                live: change.live.clone(),
                predicted: change.predicted.clone(),
            })
            .collect(),
        conflicts: diff
            .conflicts()
            .iter()
            .map(|conflict| DiffConflictView {
                field: conflict.field.clone(),
                manager: conflict.manager.clone(),
            })
            .collect(),
        truncated: diff.is_truncated(),
    }
}

/// The wire form of any `serde`-serializable enum with unit variants (`Synced`, `Healthy`, ...).
fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "Unknown".to_owned())
}

/// RFC 3339 rendering of a Kubernetes `Time`, via its own `serde` implementation.
fn time_string(time: &k8s_openapi::apimachinery::pkg::apis::meta::v1::Time) -> Option<String> {
    serde_json::to_value(time)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
}

/// The selected renderer, as a stable label.
fn renderer_label(renderer: &ferriscd_crd::RendererSpec) -> &'static str {
    match renderer {
        ferriscd_crd::RendererSpec::Auto(_) => "auto",
        ferriscd_crd::RendererSpec::PlainYaml(_) => "plainYaml",
        ferriscd_crd::RendererSpec::Kustomize(_) => "kustomize",
        ferriscd_crd::RendererSpec::Helm(_) => "helm",
    }
}

/// The wire label of a [`DiffStatus`].
///
/// Written out by hand rather than derived from `serde`: `OwnershipConflict` carries a payload, so a
/// generic "serialize and take the string" helper would reduce it to `Unknown`.
fn diff_status_label(status: &ferriscd_engine::diff::DiffStatus) -> &'static str {
    match status {
        ferriscd_engine::diff::DiffStatus::Synced => "synced",
        ferriscd_engine::diff::DiffStatus::OutOfSync => "outOfSync",
        ferriscd_engine::diff::DiffStatus::Missing => "missing",
        ferriscd_engine::diff::DiffStatus::Orphaned => "orphaned",
        ferriscd_engine::diff::DiffStatus::OwnershipConflict { .. } => "ownershipConflict",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_renderer_is_labelled() {
        use ferriscd_crd::application::{
            AutoRenderer, HelmRenderer, KustomizeRenderer, PlainYamlRenderer,
        };
        assert_eq!(
            renderer_label(&ferriscd_crd::RendererSpec::Auto(AutoRenderer {})),
            "auto"
        );
        assert_eq!(
            renderer_label(&ferriscd_crd::RendererSpec::PlainYaml(
                PlainYamlRenderer::default()
            )),
            "plainYaml"
        );
        assert_eq!(
            renderer_label(&ferriscd_crd::RendererSpec::Kustomize(
                KustomizeRenderer::default()
            )),
            "kustomize"
        );
        assert_eq!(
            renderer_label(&ferriscd_crd::RendererSpec::Helm(HelmRenderer::default())),
            "helm"
        );
    }

    /// **Finding M6.** A `v1.1` server's `SourceView` payload — no `sourceType` key at all —
    /// deserializes into a Git source instead of failing the whole response, while the **schema**
    /// keeps `sourceType` required (a `v1.2` server always sends it, and the generated TypeScript
    /// client depends on it being present).
    #[test]
    fn a_v1_1_source_view_deserializes_as_a_git_source_and_the_schema_stays_strict() {
        // Exactly what a `v1.1` server emitted: no `sourceType`, no `tag`, no `digest`.
        let payload = serde_json::json!({
            "repoUrl": "https://github.com/example/manifests",
            "path": "apps/payments",
            "targetRevision": "main",
            "renderer": "kustomize",
        });
        let view: SourceView =
            serde_json::from_value(payload.clone()).expect("a v1.1 payload must still deserialize");
        assert_eq!(
            view.source_type, "git",
            "the only kind a v1.1 server can serve"
        );
        assert_eq!(view.tag, None);
        assert_eq!(view.digest, None);
        assert_eq!(view.repo_url, "https://github.com/example/manifests");

        // A `v1.2` payload still overrides the default, so the fallback cannot mask a real OCI
        // source.
        let mut oci = payload.clone();
        oci["sourceType"] = serde_json::json!("oci");
        oci["tag"] = serde_json::json!("1.4.2");
        let view: SourceView = serde_json::from_value(oci).expect("an OCI payload must parse");
        assert_eq!(view.source_type, "oci");
        assert_eq!(view.tag.as_deref(), Some("1.4.2"));

        // The response schema is strict: `sourceType` is required even though deserialization
        // defaults it.
        let schema = serde_json::to_value(<SourceView as utoipa::PartialSchema>::schema())
            .expect("the schema must serialize");
        let required = schema["required"].as_array().cloned().unwrap_or_default();
        assert!(
            required.contains(&serde_json::json!("sourceType")),
            "the OpenAPI schema must keep `sourceType` required: {schema}"
        );
    }

    #[test]
    fn diff_statuses_are_labelled_for_the_wire() {
        use ferriscd_engine::diff::DiffStatus;
        assert_eq!(diff_status_label(&DiffStatus::Synced), "synced");
        assert_eq!(diff_status_label(&DiffStatus::OutOfSync), "outOfSync");
        assert_eq!(diff_status_label(&DiffStatus::Missing), "missing");
        assert_eq!(diff_status_label(&DiffStatus::Orphaned), "orphaned");
        assert_eq!(
            diff_status_label(&DiffStatus::OwnershipConflict {
                owner: "other/app:apps/Deployment/ns/x".to_owned()
            }),
            "ownershipConflict"
        );
    }

    /// `LiveResourceState`/`ResourceKey` round-trip through the node mapping without inventing a
    /// namespace or a health verdict.
    #[test]
    fn a_node_reports_exactly_what_the_read_returned() {
        let key = ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api");
        let node = node_view(
            &key,
            true,
            Some("OwnedBySelf"),
            &BTreeMap::from([(
                key.canonical(),
                ("Healthy".to_owned(), "all replicas are ready".to_owned()),
            )]),
        );
        assert_eq!(node.key, "apps/Deployment/payments/api");
        assert_eq!(node.health.as_deref(), Some("Healthy"));
        assert_eq!(
            node.health_message.as_deref(),
            Some("all replicas are ready")
        );
        assert_eq!(node.ownership.as_deref(), Some("OwnedBySelf"));
        assert!(node.parent.is_none());

        // A cluster-scoped resource keeps an empty namespace segment and no namespace field.
        let cluster_scoped = node_view(
            &ResourceKey::new("rbac.authorization.k8s.io", "ClusterRole", None, "admin"),
            false,
            None,
            &BTreeMap::new(),
        );
        assert_eq!(
            cluster_scoped.key,
            "rbac.authorization.k8s.io/ClusterRole//admin"
        );
        assert!(cluster_scoped.namespace.is_none());
        assert!(cluster_scoped.health.is_none());
        assert!(!cluster_scoped.present);
    }

    #[test]
    fn a_pending_operation_is_detected_but_a_blank_one_is_not() {
        let mut app = Application::new(
            "payments",
            serde_json::from_value(serde_json::json!({
                "project": "default",
                "source": {"git": {"repoURL": "https://example.com/r.git", "path": "deploy"}},
                "destination": {"namespace": "payments"},
            }))
            .expect("spec"),
        );
        assert_eq!(pending_operation(&app), PendingOperation::None);
        app.metadata.annotations = Some(BTreeMap::from([(
            annotations::OPERATION.to_owned(),
            "   ".to_owned(),
        )]));
        assert_eq!(
            pending_operation(&app),
            PendingOperation::None,
            "a blank annotation is not a request"
        );
        app.metadata.annotations = Some(BTreeMap::from([(
            annotations::OPERATION.to_owned(),
            r#"{"sync":{}}"#.to_owned(),
        )]));
        assert_eq!(
            pending_operation(&app),
            PendingOperation::ManualSync(r#"{"sync":{}}"#.to_owned())
        );
    }

    /// The slot is classified exactly as the controller reads it: a rollback request is a rollback,
    /// and every other non-blank value (the CLI's `{"sync":{"revision":"main"}}`, a broken payload)
    /// is a manual sync — so a new request can replace it instead of being refused forever.
    #[test]
    fn the_operation_slot_is_classified_the_way_the_controller_reads_it() {
        let mut app = Application::new(
            "payments",
            serde_json::from_value(serde_json::json!({
                "project": "default",
                "source": {"git": {"repoURL": "https://example.com/r.git", "path": "deploy"}},
                "destination": {"namespace": "payments"},
            }))
            .expect("spec"),
        );
        for (value, expected) in [
            (
                r#"{"rollback":{"id":3}}"#,
                PendingOperation::Rollback(r#"{"rollback":{"id":3}}"#.to_owned()),
            ),
            (
                r#"{"sync":{"revision":"main"}}"#,
                PendingOperation::ManualSync(r#"{"sync":{"revision":"main"}}"#.to_owned()),
            ),
            (
                "not json at all",
                PendingOperation::ManualSync("not json at all".to_owned()),
            ),
        ] {
            app.metadata.annotations = Some(BTreeMap::from([(
                annotations::OPERATION.to_owned(),
                value.to_owned(),
            )]));
            assert_eq!(pending_operation(&app), expected, "{value}");
        }
    }
}
