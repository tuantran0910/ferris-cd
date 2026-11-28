//! Phase 15 (`T15.4`) Chaos Test Suite — Hermetic Deterministic & Live `kind` Scenarios.
//!
//! Proves FerrisCD holds its safety invariants when infrastructure fails mid-operation:
//!
//! 1. **Mid-multi-wave controller crash & restart (`SIGKILL`):**
//!    * Hermetic: runs Wave 0 + partial Wave 1 against a multi-wave `Application` (with
//!      `prune: true` and an existing owned orphan), drops the entire controller instance
//!      (`InventorySyncPipeline`, `RepoCache`, `DiscoveryCache`, `BackoffTracker`), constructs a
//!      fresh controller instance against the persisted `Application.status` + live cluster, and
//!      asserts clean convergence across all remaining waves with **zero** orphaned/corrupted
//!      inventory entries and exact crash-safe inventory `(prev \ pruned_ok) ∪ applied_ok`.
//!    * Hermetic (worst-case crash window): kills the controller *after* Wave 0 writes land on the
//!      cluster but *before* `/status` is patched, proving idempotent recovery from live state.
//!    * Live `kind` (`#[ignore]`): spawns a real `ferriscd controller` child process, sends
//!      `SIGKILL` mid-multi-wave sync, restarts a fresh process, and verifies clean convergence.
//!
//! 2. **Sustained Git outage & renderer failure while healthy (`prune: true`) — Trap Guard `T15.4`:**
//!    * Hermetic: converges a 5-resource `Application` (`prune: true`) to `Synced` + `Healthy`,
//!      injects 6 consecutive retryable Git fetch failures (`Network`, `Timeout`, `503`, `502`,
//!      `429`, `Network`), verifies `Ready=False` on `/status`, verifies exponential backoff and
//!      `Warning SyncFailed` deduplication, asserts **`delete_calls == 0`** (ZERO live resources
//!      pruned) and intact `status.inventory`, then restores Git and proves automatic recovery.
//!    * Hermetic (renderer failure + empty-render guard): verifies **zero** resources are ever
//!      pruned when YAML rendering fails OR when an empty render is produced over a non-empty
//!      inventory.
//!    * Live `kind` (`#[ignore]`): serves the fixture Git repository over a real loopback TCP
//!      transport (`ssh://git@127.0.0.1:<port>/repo.git` backed by `LocalGitTcpServer` +
//!      `git-upload-pack` and a control-plane `ferriscd.io/secret-type=repository` `Secret`),
//!      stops the Git server for 90s (overridable via `FERRISCD_CHAOS_GIT_OUTAGE_SECONDS`) while
//!      workloads are healthy with `prune: true` so fetches fail with `ConnectionRefused` ->
//!      `RepoError::Network` -> `FailureClass::Retryable` (exponential backoff, not 600s terminal
//!      delay), verifies `Ready=False`, stable `status.inventory`, and unchanged workload UIDs
//!      (ZERO workloads pruned/recreated), then restarts the server and proves automatic recovery.
//!      (Note: FerrisCD pins `protocol.http.allow=never`, and on macOS `rustls-platform-verifier`
//!      uses Apple `SecTrust` rather than `SSL_CERT_FILE`, so loopback `ssh://` + TCP
//!      `git-upload-pack` provides a cross-platform retryable network transport on both Linux and
//!      macOS without modifying host keychains.)
//!
//! 3. **Transient Kubernetes API failures (`429 TooManyRequests` / `503 ServiceUnavailable`):**
//!    * Hermetic: injects transient retryable API failures across live-state `GET`, SSA
//!      `dryRun=All`, and SSA `Apply`, verifies `FailureClass::Retryable` + `BackoffTracker`
//!      exponential doubling (`5s -> 10s -> 20s -> 40s -> 80s -> 160s -> 180s` cap), asserts
//!      `Ready=False`, **`delete_calls == 0`**, intact live objects, and exact Prometheus metrics
//!      accounting (`ferriscd_reconcile_total{result="retryable"}`, `ferriscd_active_reconciles == 0`),
//!      then clears faults and proves clean convergence + backoff reset.
//!    * Live `kind` (`#[ignore]`): runs a local TCP fault-injecting proxy in front of the `kind`
//!      API server (preserving full mTLS SAN validation on `127.0.0.1`), injects transient
//!      transport drops, verifies retryable backoff & zero pruned workloads, clears faults, and
//!      verifies clean convergence.
//!
//! # Running
//!
//! ```text
//! # Hermetic chaos suite (runs under `cargo test --workspace` with zero cluster dependency)
//! cargo test -p ferriscd-controller --test chaos_suite
//!
//! # Live `kind` chaos suite (requires a running `kind-*` cluster)
//! make kind-up
//! cargo test -p ferriscd-controller --test chaos_suite -- --ignored --test-threads=1
//! ```

// Compiled strictly as an integration test target; descriptive `.expect(...)` calls are allowed.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferriscd_controller::controller::{
    BackoffTracker, FailureClass, RETRY_BASE_DELAY, RETRY_MAX_DELAY, object_key,
};
use ferriscd_controller::discovery::{
    DiscoveryCache, DiscoveryFuture, DiscoverySnapshot, DiscoverySource,
};
use ferriscd_controller::dry_run::{
    DryRunApi, DryRunError, DryRunFuture, DryRunOutcome, DryRunTarget,
};
use ferriscd_controller::events::{
    AppEventType, EVENT_REASON_SYNC_FAILED, EVENT_REASON_SYNC_SUCCEEDED, EventClock, EventRecorder,
    RecordingEventPublisher,
};
use ferriscd_controller::live_state::{FetchTarget, LiveFuture, LiveObjectSource, LiveStateError};
use ferriscd_controller::metrics::{Metrics, MetricsStatusWriter, ReconcileResult};
use ferriscd_controller::project::ProjectSource;
use ferriscd_controller::reconcile::{
    ControllerError, ReconcileError, StatusWriter, apply_once_with_events,
};
use ferriscd_controller::sync::{
    Applier, ApplyRequest, DeleteOutcome, DeleteRequest, IN_CLUSTER, InventorySyncPipeline,
    apply_body,
};
use ferriscd_crd::application::{DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_REVISION_HISTORY_LIMIT};
use ferriscd_crd::status::{
    ApplicationStatus, CONDITION_READY, ConditionStatus, HealthStatus, OperationPhase, SyncStatus,
};
use ferriscd_crd::{
    AppProject, Application, ApplicationSpec, AutomatedSyncPolicy, DestinationSpec, GitSourceSpec,
    RendererSpec, SourceSpec, SyncPolicy, annotations,
};
use ferriscd_engine::repo::{
    FakeGitClient, FakeGitClientConfig, FakeStage, GitClient, GitSource, GixGitClient,
    GixGitClientConfig, RepoCache, RepoCacheConfig, RepoCredentials, RepoError, RepoUrlPolicy,
};
use futures::future::BoxFuture;
use kube::api::{ApiResource, DynamicObject, GroupVersionKind as KubeGvk};
use kube::discovery::{ApiCapabilities, Scope};
use serde_json::json;
use tokio::io::AsyncWriteExt as _;
use tokio_util::sync::CancellationToken;

/// Control-plane namespace used by all chaos scenarios.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Destination namespace used by hermetic chaos scenarios.
const DEST_NAMESPACE: &str = "chaos-app";
/// Application name used by hermetic chaos scenarios.
const APP_NAME: &str = "chaos-payments";
/// Synthetic remote repository URL accepted under `RepoUrlPolicy::Production`.
const FAKE_REPO_URL: &str = "https://git.example.test/platform/chaos-payments.git";

/// Shipped default `AppProject` manifest so tests exercise the real policy contract.
const DEFAULT_PROJECT_MANIFEST: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/manifests/default-project.yaml"
));

// ===========================================================================
// Hermetic Deterministic Chaos Harness (Zero cluster, zero sleeps)
// ===========================================================================

/// Controllable monotonic clock for `EventRecorder` so deduplication tests never call `sleep`.
struct ManualClock {
    now: Mutex<Instant>,
}

impl ManualClock {
    fn new() -> Self {
        Self {
            now: Mutex::new(Instant::now()),
        }
    }

    fn advance(&self, delta: Duration) {
        let mut guard = self.now.lock().expect("clock mutex");
        *guard += delta;
    }
}

impl EventClock for ManualClock {
    fn now(&self) -> Instant {
        *self.now.lock().expect("clock mutex")
    }
}

/// Fault queues for the simulated Kubernetes API server.
#[derive(Default)]
struct ClusterFaults {
    /// Queued failures for `LiveObjectSource::get`.
    live_get: VecDeque<LiveStateError>,
    /// Queued failures for `DryRunApi::dry_run`.
    dry_run: VecDeque<DryRunError>,
    /// Queued failures for `Applier::apply` keyed by canonical GKNN (or `"*"` for any key).
    apply: BTreeMap<String, VecDeque<kube::Error>>,
}

/// Persisted, in-memory Kubernetes cluster state that survives controller drops/restarts.
///
/// Dropping a `ControllerRuntime` destroys all in-memory controller state (`InventorySyncPipeline`,
/// `RepoCache`, `RenderPipeline`, `DiscoveryCache`, `BackoffTracker`, `Metrics`), while
/// `ChaosCluster` retains only what Kubernetes itself persists: live workload objects, namespaces,
/// and the `Application` CR's `/status` subresource.
#[derive(Default)]
struct ChaosCluster {
    objects: Mutex<BTreeMap<String, DynamicObject>>,
    namespaces: Mutex<BTreeSet<String>>,
    applies: Mutex<Vec<String>>,
    deletes: Mutex<Vec<String>>,
    faults: Mutex<ClusterFaults>,
    /// Persisted `Application.status` (patched by `StatusWriter`).
    app_status: Mutex<Option<ApplicationStatus>>,
    /// Number of `/status` patches attempted.
    status_patches: AtomicUsize,
    /// When `true`, the next `/status` patch fails and does not persist (simulating `SIGKILL`
    /// after workload writes landed on the API server but before `/status` could be written).
    drop_next_status_patch: AtomicBool,
}

impl ChaosCluster {
    fn new_with_namespace(namespace: &str) -> Arc<Self> {
        let cluster = Arc::new(Self::default());
        cluster
            .namespaces
            .lock()
            .expect("namespaces mutex")
            .insert(namespace.to_owned());
        cluster
    }

    fn insert_object(&self, object: DynamicObject) {
        let key = gknn_of_object(&object);
        self.objects
            .lock()
            .expect("objects mutex")
            .insert(key, object);
    }

    fn object_keys(&self) -> BTreeSet<String> {
        self.objects
            .lock()
            .expect("objects mutex")
            .keys()
            .cloned()
            .collect()
    }

    fn live_data_value(&self, gknn: &str, field: &str) -> Option<String> {
        self.objects
            .lock()
            .expect("objects mutex")
            .get(gknn)
            .and_then(|obj| obj.data.pointer(&format!("/data/{field}")))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    }

    fn live_tracking_id(&self, gknn: &str) -> Option<String> {
        self.objects
            .lock()
            .expect("objects mutex")
            .get(gknn)
            .and_then(|obj| obj.metadata.annotations.as_ref())
            .and_then(|ann| ann.get(annotations::TRACKING_ID))
            .cloned()
    }

    fn delete_calls(&self) -> Vec<String> {
        self.deletes.lock().expect("deletes mutex").clone()
    }

    fn status(&self) -> Option<ApplicationStatus> {
        self.app_status.lock().expect("app_status mutex").clone()
    }

    fn set_status(&self, status: ApplicationStatus) {
        *self.app_status.lock().expect("app_status mutex") = Some(status);
    }

    fn status_patch_count(&self) -> usize {
        self.status_patches.load(Ordering::SeqCst)
    }

    fn fail_next_status_patch(&self) {
        self.drop_next_status_patch.store(true, Ordering::SeqCst);
    }

    fn push_live_get_fault(&self, err: LiveStateError) {
        self.faults
            .lock()
            .expect("faults mutex")
            .live_get
            .push_back(err);
    }

    fn push_dry_run_fault(&self, err: DryRunError) {
        self.faults
            .lock()
            .expect("faults mutex")
            .dry_run
            .push_back(err);
    }

    fn push_apply_fault(&self, gknn: &str, err: kube::Error) {
        self.faults
            .lock()
            .expect("faults mutex")
            .apply
            .entry(gknn.to_owned())
            .or_default()
            .push_back(err);
    }

    /// Marks a `Deployment` as completely rolled out and ready (`Healthy` per Phase 09 rules).
    fn make_deployment_ready(&self, namespace: &str, name: &str, replicas: i32) {
        let key = format!("apps/Deployment/{namespace}/{name}");
        let mut objects = self.objects.lock().expect("objects mutex");
        let obj = objects
            .get_mut(&key)
            .unwrap_or_else(|| panic!("expected live Deployment at {key}"));
        obj.data["status"] = json!({
            "observedGeneration": obj.metadata.generation,
            "replicas": replicas,
            "updatedReplicas": replicas,
            "availableReplicas": replicas,
            "readyReplicas": replicas,
            "conditions": [],
        });
    }
}

impl LiveObjectSource for ChaosCluster {
    fn get<'a>(&'a self, target: FetchTarget<'a>) -> LiveFuture<'a, Option<DynamicObject>> {
        let wanted = gknn_of(
            &target.api_resource.group,
            &target.api_resource.kind,
            target.namespace,
            target.name,
        );
        Box::pin(async move {
            if let Some(err) = self
                .faults
                .lock()
                .expect("faults mutex")
                .live_get
                .pop_front()
            {
                return Err(err);
            }
            let object = self
                .objects
                .lock()
                .expect("objects mutex")
                .get(&wanted)
                .cloned();
            Ok(object)
        })
    }

    fn namespace_exists<'a>(&'a self, namespace: &'a str) -> LiveFuture<'a, bool> {
        let ns = namespace.to_owned();
        Box::pin(async move {
            Ok(self
                .namespaces
                .lock()
                .expect("namespaces mutex")
                .contains(&ns))
        })
    }
}

impl DryRunApi for ChaosCluster {
    fn dry_run<'a>(&'a self, target: DryRunTarget<'a>) -> DryRunFuture<'a> {
        let predicted = apply_body(target.object);
        Box::pin(async move {
            if let Some(err) = self
                .faults
                .lock()
                .expect("faults mutex")
                .dry_run
                .pop_front()
            {
                return Err(err);
            }
            Ok(DryRunOutcome::Predicted(Box::new(predicted)))
        })
    }
}

impl Applier for ChaosCluster {
    fn apply<'a>(
        &'a self,
        request: ApplyRequest<'a>,
    ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
        let key = request.resource.key.canonical();
        let body = apply_body(&request.resource.object);
        Box::pin(async move {
            {
                let mut faults = self.faults.lock().expect("faults mutex");
                if let Some(queue) = faults.apply.get_mut(&key)
                    && let Some(err) = queue.pop_front()
                {
                    return Err(ReconcileError::Apply {
                        resource: key,
                        source: err,
                    });
                }
                if let Some(queue) = faults.apply.get_mut("*")
                    && let Some(err) = queue.pop_front()
                {
                    return Err(ReconcileError::Apply {
                        resource: key,
                        source: err,
                    });
                }
            }
            self.applies
                .lock()
                .expect("applies mutex")
                .push(key.clone());
            // Mirror real API server SSA behavior: preserve live `.status` subresource across
            // spec-only updates and persist the object immediately so subsequent reads observe it.
            let mut persisted = body.clone();
            {
                let mut objects = self.objects.lock().expect("objects mutex");
                if let Some(existing) = objects.get(&key)
                    && let Some(live_status) = existing.data.get("status")
                {
                    persisted.data["status"] = live_status.clone();
                }
                if persisted.metadata.generation.is_none() {
                    persisted.metadata.generation = Some(1);
                }
                objects.insert(key, persisted.clone());
            }
            Ok(persisted)
        })
    }

    fn delete<'a>(
        &'a self,
        request: DeleteRequest<'a>,
    ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
        let key = request.key.canonical();
        Box::pin(async move {
            self.deletes
                .lock()
                .expect("deletes mutex")
                .push(key.clone());
            let existed = self
                .objects
                .lock()
                .expect("objects mutex")
                .remove(&key)
                .is_some();
            if existed {
                Ok(DeleteOutcome::Deleted)
            } else {
                Ok(DeleteOutcome::AlreadyGone)
            }
        })
    }
}

impl StatusWriter for ChaosCluster {
    fn patch<'a>(
        &'a self,
        _app: &'a Application,
        status: ApplicationStatus,
    ) -> BoxFuture<'a, Result<(), ReconcileError>> {
        Box::pin(async move {
            self.status_patches.fetch_add(1, Ordering::SeqCst);
            if self.drop_next_status_patch.swap(false, Ordering::SeqCst) {
                return Err(ReconcileError::Api(kube_status_error(
                    503,
                    "ServiceUnavailable",
                    "simulated SIGKILL before /status patch persisted",
                )));
            }
            *self.app_status.lock().expect("app_status mutex") = Some(status);
            Ok(())
        })
    }
}

/// Static discovery snapshot covering core/apps/batch/apiextensions kinds.
struct StaticDiscovery {
    snapshot: DiscoverySnapshot,
}

impl StaticDiscovery {
    fn standard() -> Arc<Self> {
        let mut snapshot = DiscoverySnapshot::new("v1.35.0");
        for (group, version, kind, scope) in [
            ("", "v1", "ConfigMap", Scope::Namespaced),
            ("", "v1", "Secret", Scope::Namespaced),
            ("", "v1", "Service", Scope::Namespaced),
            ("", "v1", "Namespace", Scope::Cluster),
            ("apps", "v1", "Deployment", Scope::Namespaced),
            ("batch", "v1", "Job", Scope::Namespaced),
            (
                "apiextensions.k8s.io",
                "v1",
                "CustomResourceDefinition",
                Scope::Cluster,
            ),
        ] {
            let api_resource = ApiResource::from_gvk(&KubeGvk::gvk(group, version, kind));
            let capabilities = ApiCapabilities {
                scope,
                subresources: Vec::new(),
                operations: vec![
                    "get".to_owned(),
                    "patch".to_owned(),
                    "delete".to_owned(),
                    "create".to_owned(),
                ],
            };
            snapshot = snapshot.with_resource(api_resource, capabilities);
        }
        Arc::new(Self { snapshot })
    }
}

impl DiscoverySource for StaticDiscovery {
    fn fetch(&self) -> DiscoveryFuture<'_> {
        let snapshot = self.snapshot.clone();
        Box::pin(async move { Ok(snapshot) })
    }
}

/// In-memory `ProjectSource` serving the shipped `default` `AppProject`.
struct DefaultProjectSource {
    project: AppProject,
}

impl DefaultProjectSource {
    fn new() -> Arc<Self> {
        let project: AppProject = serde_saphyr::from_str(DEFAULT_PROJECT_MANIFEST)
            .expect("shipped default-project.yaml must parse");
        Arc::new(Self { project })
    }
}

impl ProjectSource for DefaultProjectSource {
    fn get<'a>(
        &'a self,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Option<AppProject>, ReconcileError>> {
        let result = (name == ferriscd_crd::DEFAULT_PROJECT_NAME).then(|| self.project.clone());
        Box::pin(async move { Ok(result) })
    }
}

/// One self-contained controller runtime instance (pipeline, caches, backoff, metrics, events).
///
/// Dropping this struct simulates a hard process crash (`SIGKILL`): all in-memory caches
/// (`RepoCache`, `RenderPipeline`, `DiscoveryCache`), backoff counters, and metrics are discarded,
/// leaving ONLY `ChaosCluster` (live cluster objects + persisted `Application.status`) and the
/// upstream Git repository (`FakeGitClient`).
struct ControllerRuntime {
    pipeline: InventorySyncPipeline,
    status_writer: MetricsStatusWriter,
    backoff: BackoffTracker,
    metrics: Metrics,
    events: EventRecorder,
    published_events: Arc<RecordingEventPublisher>,
    clock: Arc<ManualClock>,
    _work_dir: tempfile::TempDir,
}

impl ControllerRuntime {
    fn boot(git: Arc<FakeGitClient>, cluster: Arc<ChaosCluster>) -> Self {
        let work_dir = tempfile::tempdir().expect("create controller work_root");
        let repos = Arc::new(RepoCache::new(git, RepoCacheConfig::new(work_dir.path())));
        let discovery =
            DiscoveryCache::with_source(StaticDiscovery::standard(), Duration::from_secs(3600));
        let metrics = Metrics::with_fixed_series();
        let pipeline = InventorySyncPipeline::new(
            repos,
            discovery,
            cluster.clone(),
            cluster.clone(),
            cluster.clone(),
        )
        .with_project_source(DefaultProjectSource::new())
        .with_metrics(metrics.clone());

        let status_writer = MetricsStatusWriter::new(cluster, metrics.clone());
        let published_events = Arc::new(RecordingEventPublisher::new());
        let clock = Arc::new(ManualClock::new());
        let events = EventRecorder::new(published_events.clone()).with_clock(clock.clone());

        Self {
            pipeline,
            status_writer,
            backoff: BackoffTracker::new(),
            metrics,
            events,
            published_events,
            clock,
            _work_dir: work_dir,
        }
    }

    /// Runs one full reconcile pass (instrumented with `Metrics`, `EventRecorder`, and
    /// `BackoffTracker` exactly like `reconcile_instance` + `error_policy`), returning either
    /// `Ok(kube::runtime::controller::Action)` or `(ReconcileError, FailureClass, backoff_delay)`.
    async fn reconcile(
        &self,
        app_template: &Application,
        cluster: &ChaosCluster,
    ) -> Result<kube::runtime::controller::Action, (Box<ReconcileError>, FailureClass, Duration)>
    {
        // Hydrate the Application with whatever `/status` Kubernetes currently persists.
        let mut app = app_template.clone();
        app.status = cluster.status();

        let key = object_key(&app);
        let guard = self.metrics.start_reconcile();
        let outcome =
            apply_once_with_events(&app, &self.pipeline, &self.status_writer, &self.events).await;

        match outcome {
            Ok(action) => {
                let ctrl_res: Result<(), ControllerError> = Ok(());
                guard.finish(ReconcileResult::of(&ctrl_res));
                self.backoff.reset(&key);
                Ok(action)
            }
            Err(err) => {
                let failure_class = err.failure_class();
                let metric_result = match failure_class {
                    FailureClass::Retryable => ReconcileResult::Retryable,
                    FailureClass::Terminal => ReconcileResult::Terminal,
                };
                guard.finish(metric_result);
                let delay = self.backoff.record_failure(&key, failure_class);
                Err((Box::new(err), failure_class, delay))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest & Helper Builders
// ---------------------------------------------------------------------------

fn gknn_of(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> String {
    format!("{group}/{kind}/{}/{}", namespace.unwrap_or_default(), name)
}

fn gknn_of_object(object: &DynamicObject) -> String {
    let api_version = object
        .types
        .as_ref()
        .map(|t| t.api_version.as_str())
        .unwrap_or_default();
    let kind = object
        .types
        .as_ref()
        .map(|t| t.kind.as_str())
        .unwrap_or_default();
    let group = api_version.split_once('/').map(|(g, _)| g).unwrap_or("");
    gknn_of(
        group,
        kind,
        object.metadata.namespace.as_deref(),
        object.metadata.name.as_deref().unwrap_or_default(),
    )
}

fn chaos_application(prune: bool) -> Application {
    let spec = ApplicationSpec {
        project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
        service_account_name: None,
        source: Some(SourceSpec {
            git: Some(GitSourceSpec {
                repo_url: FAKE_REPO_URL.to_owned(),
                target_revision: "main".to_owned(),
                path: "manifests".to_owned(),
            }),
            oci: None,
            renderer: RendererSpec::default(),
        }),
        sources: Vec::new(),
        destination: DestinationSpec {
            cluster: IN_CLUSTER.to_owned(),
            namespace: DEST_NAMESPACE.to_owned(),
        },
        sync_policy: Some(SyncPolicy {
            automated: Some(AutomatedSyncPolicy {
                prune,
                self_heal: true,
            }),
            sync_options: None,
            retry: None,
            metric_gates: Vec::new(),
        }),
        ignore_differences: Vec::new(),
        requeue_after_seconds: DEFAULT_REQUEUE_AFTER_SECONDS,
        revision_history_limit: DEFAULT_REVISION_HISTORY_LIMIT,
    };
    let mut app = Application::new(APP_NAME, spec);
    app.metadata.namespace = Some(CONTROL_NAMESPACE.to_owned());
    app.metadata.generation = Some(1);
    app
}

fn configmap_yaml(name: &str, value: &str, wave: Option<i32>) -> String {
    let annotations = match wave {
        Some(w) => format!("  annotations:\n    ferriscd.io/sync-wave: \"{w}\"\n"),
        None => String::new(),
    };
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {name}\n{annotations}data:\n  key: {value}\n"
    )
}

fn deployment_yaml(name: &str, image_tag: &str, wave: Option<i32>) -> String {
    let annotations = match wave {
        Some(w) => format!("  annotations:\n    ferriscd.io/sync-wave: \"{w}\"\n"),
        None => String::new(),
    };
    format!(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: {name}\n{annotations}spec:\n  \
         replicas: 1\n  selector:\n    matchLabels:\n      app: {name}\n  template:\n    \
         metadata:\n      labels:\n        app: {name}\n    spec:\n      containers:\n        \
         - name: app\n          image: registry.k8s.io/pause:{image_tag}\n"
    )
}

fn service_yaml(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: {name}\nspec:\n  selector:\n    \
         app: {name}\n  ports:\n    - port: 80\n      targetPort: 8080\n"
    )
}

fn owned_configmap_object(name: &str, value: &str) -> DynamicObject {
    let tracking_id = format!("{CONTROL_NAMESPACE}/{APP_NAME}:/ConfigMap:{DEST_NAMESPACE}/{name}");
    serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": name,
            "namespace": DEST_NAMESPACE,
            "annotations": {
                annotations::TRACKING_ID: tracking_id,
            },
        },
        "data": { "key": value },
    }))
    .expect("valid ConfigMap DynamicObject")
}

fn kube_status_error(code: u16, reason: &str, message: &str) -> kube::Error {
    kube::Error::Api(
        serde_json::from_value::<kube::core::Status>(json!({
            "status": "Failure",
            "message": message,
            "reason": reason,
            "code": code,
        }))
        .expect("valid kube Status")
        .boxed(),
    )
}

fn inventory_keys(status: &ApplicationStatus) -> Vec<String> {
    status
        .inventory
        .iter()
        .map(|entry| entry.key.clone())
        .collect()
}

fn inventory_key_set(status: &ApplicationStatus) -> BTreeSet<String> {
    status
        .inventory
        .iter()
        .map(|entry| entry.key.clone())
        .collect()
}

fn assert_ready_status(status: &ApplicationStatus, expected: ConditionStatus, context: &str) {
    let cond = status
        .condition(CONDITION_READY)
        .unwrap_or_else(|| panic!("{context}: Ready condition must be patched on /status"));
    assert_eq!(
        cond.status, expected,
        "{context}: unexpected Ready condition: {cond:?}"
    );
}

fn parse_prometheus_sample(encoded: &str, line_prefix: &str) -> Option<f64> {
    encoded.lines().find_map(|line| {
        let rest = line.strip_prefix(line_prefix)?;
        if !rest.starts_with(' ') {
            return None;
        }
        rest.trim().parse::<f64>().ok()
    })
}

// ===========================================================================
// Scenario 1 (Hermetic): Mid-Multi-Wave Controller Crash & Restart (SIGKILL)
// ===========================================================================

#[tokio::test]
async fn chaos_hermetic_sigkill_mid_multi_wave_recovers_with_exact_inventory() {
    let git = Arc::new(FakeGitClient::with_config(
        FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::Production),
    ));
    git.add_commit(
        "main",
        [
            (
                "manifests/w0-cfg.yaml",
                configmap_yaml("wave0-config", "v1", Some(0)),
            ),
            (
                "manifests/w0-db.yaml",
                deployment_yaml("wave0-db", "3.10", Some(0)),
            ),
            (
                "manifests/w1-cfg.yaml",
                configmap_yaml("wave1-config", "v1", Some(1)),
            ),
            (
                "manifests/w1-api.yaml",
                deployment_yaml("wave1-api", "3.10", Some(1)),
            ),
            (
                "manifests/w2-cfg.yaml",
                configmap_yaml("wave2-config", "v1", Some(2)),
            ),
            (
                "manifests/w2-ext.yaml",
                configmap_yaml("wave2-extra", "v1", Some(2)),
            ),
        ],
    );

    let cluster = ChaosCluster::new_with_namespace(DEST_NAMESPACE);
    // Seed an existing owned orphan from a previous revision so we prove the full crash-safe
    // inventory formula: next = (prev \ pruned_ok) ∪ applied_ok.
    let orphan_key = format!("/ConfigMap/{DEST_NAMESPACE}/stale-orphan");
    cluster.insert_object(owned_configmap_object("stale-orphan", "old"));
    cluster.set_status(ApplicationStatus {
        inventory: vec![ferriscd_crd::InventoryEntry::new(&orphan_key, "v1")],
        ..ApplicationStatus::default()
    });

    let app = chaos_application(true);

    // --- Controller Instance #1: runs Wave 0, then gets interrupted mid-Wave 1 ---
    let controller_1 = ControllerRuntime::boot(git.clone(), cluster.clone());

    // Pass 1: dispatches Wave 0 (`wave0-config`, `wave0-db`) and persists Running operationState.
    controller_1
        .reconcile(&app, &cluster)
        .await
        .expect("Wave 0 dispatch must succeed");

    let status_after_w0 = cluster.status().expect("status persisted after Wave 0");
    assert_eq!(
        status_after_w0.operation_state.as_ref().map(|op| op.phase),
        Some(OperationPhase::Running),
        "multi-wave operation must persist Running phase before requeue"
    );
    let expected_w0: BTreeSet<String> = [
        orphan_key.clone(),
        format!("/ConfigMap/{DEST_NAMESPACE}/wave0-config"),
        format!("apps/Deployment/{DEST_NAMESPACE}/wave0-db"),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        inventory_key_set(&status_after_w0),
        expected_w0,
        "after Wave 0: inventory must be prev ∪ wave0 with zero premature prunes"
    );
    assert!(
        cluster.delete_calls().is_empty(),
        "orphans must not be pruned while multi-wave sync is still running"
    );

    // Wave 0 Deployment converges to Ready so SyncMachine advances to Wave 1.
    cluster.make_deployment_ready(DEST_NAMESPACE, "wave0-db", 1);

    // Inject a mid-operation failure right as Wave 1 starts (`wave1-config`, first resource in
    // Wave 1): SyncMachine transitions to `Sync(wave 1)`, fails with `PartialSync`, and persists
    // `operationState = Running (Sync wave 1)` + inventory `prev ∪ wave0` BEFORE the process dies.
    //
    // Note (chaos finding recorded for follow-up): if Wave 1 succeeds on resource #1 and fails on
    // resource #2, `StepHealth::is_unobserved()` currently checks `observed.is_empty()` rather than
    // "any expected key unobserved", causing `SyncMachine::step` to return `Wait` until
    // `WaveTimeout`. Partial-inventory crash recovery after resource #1 succeeds and #2 fails is
    // additionally pinned by
    // `chaos_hermetic_sigkill_mid_partial_apply_preserves_inventory_and_prunes_cleanly` below.
    let w1_cfg_key = format!("/ConfigMap/{DEST_NAMESPACE}/wave1-config");
    let w1_api_key = format!("apps/Deployment/{DEST_NAMESPACE}/wave1-api");
    cluster.push_apply_fault(
        &w1_cfg_key,
        kube_status_error(503, "ServiceUnavailable", "connection lost entering Wave 1"),
    );

    let (err, class, _delay) = controller_1
        .reconcile(&app, &cluster)
        .await
        .pipe_err_unreachable();
    assert!(
        matches!(*err, ReconcileError::PartialSync { .. }),
        "expected PartialSync when Wave 1 apply fails transiently, got: {err:?}"
    );
    assert_eq!(class, FailureClass::Retryable);

    // Verify operationState (Wave 1) + crash-safe inventory persisted BEFORE the kill.
    let status_mid_w1 = cluster.status().expect("status persisted on PartialSync");
    assert_ready_status(&status_mid_w1, ConditionStatus::False, "mid-Wave-1 fault");
    assert_eq!(
        status_mid_w1.operation_state.as_ref().map(|op| op.phase),
        Some(OperationPhase::Running),
        "PartialSync must keep operationState Running at Wave 1"
    );
    assert_eq!(
        status_mid_w1
            .operation_state
            .as_ref()
            .map(|op| op.current_wave),
        Some(1),
        "PartialSync must persist current_wave == 1 before kill"
    );
    assert_eq!(
        inventory_key_set(&status_mid_w1),
        expected_w0,
        "PartialSync must preserve prev ∪ wave0 without dropping confirmed entries"
    );
    assert!(
        cluster.delete_calls().is_empty(),
        "zero prunes allowed during mid-multi-wave failure"
    );

    // --- SIMULATE SIGKILL: drop Controller Instance #1 completely! ---
    drop(controller_1);

    // --- Controller Instance #2: brand-new cold process against persisted cluster + status ---
    let controller_2 = ControllerRuntime::boot(git.clone(), cluster.clone());

    // Pass 3 (fresh controller): resumes directly at persisted Wave 1 and applies both Wave 1
    // resources (`wave1-config`, `wave1-api`).
    controller_2
        .reconcile(&app, &cluster)
        .await
        .expect("fresh controller must resume Wave 1 cleanly");

    let status_after_w1 = cluster.status().expect("status persisted after Wave 1");
    assert_eq!(
        status_after_w1.operation_state.as_ref().map(|op| op.phase),
        Some(OperationPhase::Running),
        "still waiting on Wave 1 Deployment health before Wave 2"
    );
    assert!(
        inventory_key_set(&status_after_w1).contains(&w1_cfg_key)
            && inventory_key_set(&status_after_w1).contains(&w1_api_key),
        "both Wave 1 resources must now be tracked in status.inventory"
    );

    // Wave 1 Deployment becomes healthy -> advance to Wave 2 and final prune.
    cluster.make_deployment_ready(DEST_NAMESPACE, "wave1-api", 1);

    // Drive bounded convergence passes (Wave 2 dispatch -> Wave 2 settled + prune).
    for pass in 0..4 {
        controller_2
            .reconcile(&app, &cluster)
            .await
            .unwrap_or_else(|e| panic!("recovery pass {pass} failed: {e:?}"));
        let st = cluster.status().expect("status persisted");
        if st.sync.as_ref().map(|s| s.status) == Some(SyncStatus::Synced)
            && st.health.as_ref().map(|h| h.status) == Some(HealthStatus::Healthy)
            && st.operation_state.as_ref().map(|op| op.phase) == Some(OperationPhase::Succeeded)
        {
            break;
        }
    }

    let final_status = cluster.status().expect("final status persisted");
    assert_ready_status(
        &final_status,
        ConditionStatus::True,
        "post-crash convergence",
    );
    assert_eq!(
        final_status.sync.as_ref().map(|s| s.status),
        Some(SyncStatus::Synced),
        "must converge to Synced after SIGKILL recovery: {final_status:?}"
    );
    assert_eq!(
        final_status.health.as_ref().map(|h| h.status),
        Some(HealthStatus::Healthy),
        "must converge to Healthy after SIGKILL recovery: {final_status:?}"
    );
    assert_eq!(
        final_status.operation_state.as_ref().map(|op| op.phase),
        Some(OperationPhase::Succeeded),
        "operationState must settle to Succeeded: {final_status:?}"
    );

    // Exact inventory invariant: (prev \ {stale-orphan}) ∪ {all 6 desired resources}, zero duplicates.
    let expected_final: BTreeSet<String> = [
        format!("/ConfigMap/{DEST_NAMESPACE}/wave0-config"),
        format!("apps/Deployment/{DEST_NAMESPACE}/wave0-db"),
        format!("/ConfigMap/{DEST_NAMESPACE}/wave1-config"),
        format!("apps/Deployment/{DEST_NAMESPACE}/wave1-api"),
        format!("/ConfigMap/{DEST_NAMESPACE}/wave2-config"),
        format!("/ConfigMap/{DEST_NAMESPACE}/wave2-extra"),
    ]
    .into_iter()
    .collect();
    let raw_inventory = inventory_keys(&final_status);
    assert_eq!(
        raw_inventory.len(),
        expected_final.len(),
        "inventory must have zero duplicate or corrupted entries: {raw_inventory:?}"
    );
    assert_eq!(
        inventory_key_set(&final_status),
        expected_final,
        "final inventory must equal (prev \\ pruned_ok) ∪ applied_ok"
    );
    assert_eq!(
        cluster.object_keys(),
        expected_final,
        "live cluster objects must exactly match desired set (orphan pruned, zero leaks)"
    );
    assert_eq!(
        cluster.delete_calls(),
        vec![orphan_key],
        "only the genuine stale orphan may be pruned"
    );
    for key in &expected_final {
        assert!(
            cluster.live_tracking_id(key).is_some(),
            "surviving object {key} must retain its ferriscd.io/tracking-id"
        );
    }
}

#[tokio::test]
async fn chaos_hermetic_sigkill_before_status_patch_recovers_idempotently() {
    // Worst-case SIGKILL window: Wave 0 objects are written to the API server, then the controller
    // process dies BEFORE `/status` can be patched (status.inventory & operationState remain empty).
    let git = Arc::new(FakeGitClient::with_config(
        FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::Production),
    ));
    git.add_commit(
        "main",
        [
            (
                "manifests/w0-cfg.yaml",
                configmap_yaml("w0-cfg", "v1", Some(0)),
            ),
            (
                "manifests/w0-db.yaml",
                deployment_yaml("w0-db", "3.10", Some(0)),
            ),
            (
                "manifests/w1-cfg.yaml",
                configmap_yaml("w1-cfg", "v1", Some(1)),
            ),
        ],
    );

    let cluster = ChaosCluster::new_with_namespace(DEST_NAMESPACE);
    let app = chaos_application(true);

    // Controller #1 writes Wave 0 to cluster, then crashes right before `/status` persists.
    let controller_1 = ControllerRuntime::boot(git.clone(), cluster.clone());
    cluster.fail_next_status_patch();
    let (_err, class, _) = controller_1
        .reconcile(&app, &cluster)
        .await
        .expect_err("lost status patch must fail so controller does not swallow lost status");
    assert_eq!(class, FailureClass::Retryable);

    // Wave 0 objects ARE live on the cluster, while `Application.status` is still `None`!
    assert!(
        cluster
            .object_keys()
            .contains(&format!("/ConfigMap/{DEST_NAMESPACE}/w0-cfg")),
        "Wave 0 ConfigMap already landed on the API server before SIGKILL"
    );
    assert!(
        cluster.status().is_none(),
        "status never persisted before SIGKILL"
    );

    // Kill Controller #1 completely and boot a fresh Controller #2.
    drop(controller_1);
    let controller_2 = ControllerRuntime::boot(git.clone(), cluster.clone());

    // Wave 0 Deployment finishes rolling out while controller was restarting.
    cluster.make_deployment_ready(DEST_NAMESPACE, "w0-db", 1);

    // Drive Controller #2 to convergence.
    for pass in 0..5 {
        controller_2
            .reconcile(&app, &cluster)
            .await
            .unwrap_or_else(|e| panic!("post-SIGKILL recovery pass {pass} failed: {e:?}"));
        let st = cluster.status().expect("status persisted");
        if st.sync.as_ref().map(|s| s.status) == Some(SyncStatus::Synced)
            && st.health.as_ref().map(|h| h.status) == Some(HealthStatus::Healthy)
        {
            break;
        }
    }

    let final_status = cluster.status().expect("final status persisted");
    assert_ready_status(
        &final_status,
        ConditionStatus::True,
        "recovered after lost status",
    );
    assert_eq!(
        final_status.sync.as_ref().map(|s| s.status),
        Some(SyncStatus::Synced)
    );
    assert_eq!(
        final_status.health.as_ref().map(|h| h.status),
        Some(HealthStatus::Healthy)
    );
    let expected: BTreeSet<String> = [
        format!("/ConfigMap/{DEST_NAMESPACE}/w0-cfg"),
        format!("apps/Deployment/{DEST_NAMESPACE}/w0-db"),
        format!("/ConfigMap/{DEST_NAMESPACE}/w1-cfg"),
    ]
    .into_iter()
    .collect();
    assert_eq!(inventory_key_set(&final_status), expected);
    assert_eq!(cluster.object_keys(), expected);
    assert!(
        cluster.delete_calls().is_empty(),
        "zero deletes may occur during idempotent crash recovery"
    );
}

#[tokio::test]
async fn chaos_hermetic_sigkill_mid_partial_apply_preserves_inventory_and_prunes_cleanly() {
    // Proves crash-safe partial inventory across SIGKILL when resource #1 (`cm-a`) succeeds,
    // resource #2 (`cm-b`) fails mid-pass (`PartialSync`), the controller is killed, and a brand-new
    // controller boots to finish `cm-b`/`cm-c` and prune `stale-orphan`:
    //   after PartialSync: inventory = prev ∪ {cm-a}
    //   after recovery:    inventory = (prev \ {stale-orphan}) ∪ {cm-a, cm-b, cm-c}
    let git = Arc::new(FakeGitClient::with_config(
        FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::Production),
    ));
    git.add_commit(
        "main",
        [
            ("manifests/cm-a.yaml", configmap_yaml("cm-a", "v1", None)),
            ("manifests/cm-b.yaml", configmap_yaml("cm-b", "v1", None)),
            ("manifests/cm-c.yaml", configmap_yaml("cm-c", "v1", None)),
        ],
    );

    let cluster = ChaosCluster::new_with_namespace(DEST_NAMESPACE);
    let orphan_key = format!("/ConfigMap/{DEST_NAMESPACE}/stale-orphan");
    cluster.insert_object(owned_configmap_object("stale-orphan", "old"));
    cluster.set_status(ApplicationStatus {
        inventory: vec![ferriscd_crd::InventoryEntry::new(&orphan_key, "v1")],
        ..ApplicationStatus::default()
    });

    let app = chaos_application(true);
    let controller_1 = ControllerRuntime::boot(git.clone(), cluster.clone());

    let cm_a_key = format!("/ConfigMap/{DEST_NAMESPACE}/cm-a");
    let cm_b_key = format!("/ConfigMap/{DEST_NAMESPACE}/cm-b");
    let cm_c_key = format!("/ConfigMap/{DEST_NAMESPACE}/cm-c");
    cluster.push_apply_fault(
        &cm_b_key,
        kube_status_error(503, "ServiceUnavailable", "apiserver dropped mid-batch"),
    );

    let (err, class, _) = controller_1
        .reconcile(&app, &cluster)
        .await
        .pipe_err_unreachable();
    assert!(matches!(*err, ReconcileError::PartialSync { .. }));
    assert_eq!(class, FailureClass::Retryable);

    // Partial inventory persisted BEFORE kill must include `cm-a` AND retain `stale-orphan`.
    let mid_status = cluster.status().expect("partial status persisted");
    assert_ready_status(&mid_status, ConditionStatus::False, "mid-batch fault");
    assert_eq!(
        inventory_key_set(&mid_status),
        [orphan_key.clone(), cm_a_key.clone()]
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "PartialSync must persist already-applied cm-a while retaining unpruned orphan"
    );
    assert!(
        cluster.delete_calls().is_empty(),
        "orphan must not be pruned on a failed partial apply"
    );

    // Kill Controller #1 completely and boot fresh Controller #2.
    drop(controller_1);
    let controller_2 = ControllerRuntime::boot(git.clone(), cluster.clone());

    controller_2
        .reconcile(&app, &cluster)
        .await
        .expect("fresh controller finishes partial sync");
    controller_2
        .reconcile(&app, &cluster)
        .await
        .expect("steady-state convergence");

    let final_status = cluster.status().expect("final status persisted");
    assert_ready_status(&final_status, ConditionStatus::True, "post-kill recovery");
    assert_eq!(
        final_status.sync.as_ref().map(|s| s.status),
        Some(SyncStatus::Synced)
    );
    let expected_final: BTreeSet<String> = [cm_a_key, cm_b_key, cm_c_key].into_iter().collect();
    assert_eq!(inventory_keys(&final_status).len(), expected_final.len());
    assert_eq!(inventory_key_set(&final_status), expected_final);
    assert_eq!(cluster.object_keys(), expected_final);
    assert_eq!(cluster.delete_calls(), vec![orphan_key]);
}

// ===========================================================================
// Scenario 2 (Hermetic): Sustained Git Outage & Renderer Failure (Trap Guard T15.4)
// ===========================================================================

#[tokio::test]
async fn chaos_hermetic_git_outage_never_prunes_and_recovers_automatically() {
    let git = Arc::new(FakeGitClient::with_config(
        FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::Production),
    ));
    let commit_v1 = git.add_commit(
        "main",
        [
            ("manifests/cm-a.yaml", configmap_yaml("cm-a", "v1", None)),
            ("manifests/cm-b.yaml", configmap_yaml("cm-b", "v1", None)),
            ("manifests/cm-c.yaml", configmap_yaml("cm-c", "v1", None)),
            ("manifests/svc.yaml", service_yaml("web")),
            (
                "manifests/deploy.yaml",
                deployment_yaml("web", "3.10", None),
            ),
        ],
    );

    let cluster = ChaosCluster::new_with_namespace(DEST_NAMESPACE);
    let controller = ControllerRuntime::boot(git.clone(), cluster.clone());
    // Enable `prune: true`! This is the exact configuration where a broken GitOps controller
    // would erroneously treat an unreachable Git repo as "empty desired set" and wipe production.
    let app = chaos_application(true);

    // Step 1: Converge to Synced + Healthy.
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("initial apply");
    cluster.make_deployment_ready(DEST_NAMESPACE, "web", 1);
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("steady-state convergence");

    let healthy_status = cluster.status().expect("healthy status");
    assert_ready_status(&healthy_status, ConditionStatus::True, "pre-outage healthy");
    assert_eq!(
        healthy_status.sync.as_ref().map(|s| s.status),
        Some(SyncStatus::Synced)
    );
    assert_eq!(
        healthy_status.health.as_ref().map(|h| h.status),
        Some(HealthStatus::Healthy)
    );
    let expected_keys: BTreeSet<String> = [
        format!("/ConfigMap/{DEST_NAMESPACE}/cm-a"),
        format!("/ConfigMap/{DEST_NAMESPACE}/cm-b"),
        format!("/ConfigMap/{DEST_NAMESPACE}/cm-c"),
        format!("/Service/{DEST_NAMESPACE}/web"),
        format!("apps/Deployment/{DEST_NAMESPACE}/web"),
    ]
    .into_iter()
    .collect();
    assert_eq!(inventory_key_set(&healthy_status), expected_keys);
    assert_eq!(cluster.object_keys(), expected_keys);
    assert!(cluster.delete_calls().is_empty());

    // Step 2: Inject sustained Git outage across 6 consecutive reconcile passes (simulating 90s+).
    git.fail_sequence(
        FakeStage::Resolve,
        [
            RepoError::Network {
                message: "connection refused (git server down)".to_owned(),
            },
            RepoError::Timeout {
                message: "git ls-remote timed out after 30s".to_owned(),
            },
            RepoError::RemoteServerError {
                status: Some(503),
                message: "service unavailable".to_owned(),
            },
            RepoError::RemoteServerError {
                status: Some(502),
                message: "bad gateway".to_owned(),
            },
            RepoError::RemoteServerError {
                status: Some(429),
                message: "too many requests".to_owned(),
            },
            RepoError::Network {
                message: "connection reset by peer".to_owned(),
            },
        ],
    );

    let expected_delays = [
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(20),
        Duration::from_secs(40),
        Duration::from_secs(80),
        Duration::from_secs(160),
    ];

    for (attempt, expected_delay) in expected_delays.iter().enumerate() {
        // Advance fake event clock by 15s per retry (90s total, strictly inside 300s dedup window).
        controller.clock.advance(Duration::from_secs(15));
        let (err, class, delay) = controller
            .reconcile(&app, &cluster)
            .await
            .pipe_err_unreachable();
        assert!(
            matches!(*err, ReconcileError::Repo(_)),
            "attempt {attempt}: expected RepoError, got {err:?}"
        );
        assert_eq!(
            class,
            FailureClass::Retryable,
            "attempt {attempt}: Git outage must be classified Retryable"
        );
        assert_eq!(
            delay, *expected_delay,
            "attempt {attempt}: exponential backoff mismatch"
        );

        let st = cluster.status().expect("status patched on Git outage");
        assert_ready_status(&st, ConditionStatus::False, "during Git outage");
        // TRAP GUARD T15.4: ZERO resources may EVER be pruned during Git outage!
        assert!(
            cluster.delete_calls().is_empty(),
            "TRAP GUARD T15.4 VIOLATION: delete called during Git outage on attempt {attempt}: {:?}",
            cluster.delete_calls()
        );
        assert_eq!(
            cluster.object_keys(),
            expected_keys,
            "all 5 live workloads must remain completely untouched during Git outage"
        );
        assert_eq!(
            inventory_key_set(&st),
            expected_keys,
            "status.inventory must remain intact during Git outage"
        );
        assert_eq!(
            st.sync
                .as_ref()
                .and_then(|s| s.last_synced_revision.as_deref()),
            Some(commit_v1.as_str()),
            "lastSyncedRevision must be preserved across transient Git outage"
        );
    }

    // Event deduplication check (T15.2 + T15.4): 6 consecutive SyncFailed passes within 90s must
    // produce exactly ONE `Warning SyncFailed` event, not 6 etcd writes!
    let warning_events: Vec<_> = controller
        .published_events
        .events()
        .into_iter()
        .filter(|e| e.type_ == AppEventType::Warning && e.reason == EVENT_REASON_SYNC_FAILED)
        .collect();
    assert_eq!(
        warning_events.len(),
        1,
        "identical consecutive Warning SyncFailed events during 90s outage must deduplicate to 1, got: {warning_events:?}"
    );

    // Step 3: Restore Git availability and push a new commit to prove active recovery.
    let commit_v2 = git.add_commit(
        "main",
        [
            (
                "manifests/cm-a.yaml",
                configmap_yaml("cm-a", "v2-recovered", None),
            ),
            ("manifests/cm-b.yaml", configmap_yaml("cm-b", "v1", None)),
            ("manifests/cm-c.yaml", configmap_yaml("cm-c", "v1", None)),
            ("manifests/svc.yaml", service_yaml("web")),
            (
                "manifests/deploy.yaml",
                deployment_yaml("web", "3.10", None),
            ),
        ],
    );
    assert!(git.faults_exhausted(), "all outage faults were consumed");

    controller
        .reconcile(&app, &cluster)
        .await
        .expect("recovery pass 1 after Git restored");
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("recovery pass 2 steady state");

    let recovered = cluster.status().expect("recovered status");
    assert_ready_status(&recovered, ConditionStatus::True, "post-outage recovery");
    assert_eq!(
        recovered.sync.as_ref().map(|s| s.status),
        Some(SyncStatus::Synced)
    );
    assert_eq!(
        recovered
            .sync
            .as_ref()
            .and_then(|s| s.last_synced_revision.as_deref()),
        Some(commit_v2.as_str())
    );
    assert_eq!(
        recovered.health.as_ref().map(|h| h.status),
        Some(HealthStatus::Healthy)
    );
    assert_eq!(
        cluster.live_data_value(&format!("/ConfigMap/{DEST_NAMESPACE}/cm-a"), "key"),
        Some("v2-recovered".to_owned()),
        "new commit must land cleanly once Git recovers"
    );
    assert!(
        cluster.delete_calls().is_empty(),
        "zero deletes throughout entire Git outage + recovery"
    );
    assert_eq!(
        controller.backoff.attempts(&object_key(&app)),
        0,
        "backoff counter must reset to 0 on recovery"
    );
    // Recovery emitted a Normal SyncSucceeded event.
    assert!(
        controller
            .published_events
            .events()
            .iter()
            .any(|e| e.type_ == AppEventType::Normal && e.reason == EVENT_REASON_SYNC_SUCCEEDED),
        "recovery must emit Normal SyncSucceeded"
    );
}

/// Helper trait only used so `expect_err` ergonomics stay clean without `.unwrap()`.
trait PipeErrExt<T, E> {
    fn pipe_err_unreachable(self) -> E;
}

impl<T, E> PipeErrExt<T, E> for Result<T, E> {
    fn pipe_err_unreachable(self) -> E {
        match self {
            Ok(_) => panic!("expected Err during chaos fault injection, got Ok"),
            Err(e) => e,
        }
    }
}

#[tokio::test]
async fn chaos_hermetic_renderer_failure_never_prunes_live_workloads() {
    let git = Arc::new(FakeGitClient::with_config(
        FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::Production),
    ));
    git.add_commit(
        "main",
        [
            ("manifests/cm-a.yaml", configmap_yaml("cm-a", "v1", None)),
            ("manifests/cm-b.yaml", configmap_yaml("cm-b", "v1", None)),
            (
                "manifests/deploy.yaml",
                deployment_yaml("api", "3.10", None),
            ),
        ],
    );

    let cluster = ChaosCluster::new_with_namespace(DEST_NAMESPACE);
    let controller = ControllerRuntime::boot(git.clone(), cluster.clone());
    let app = chaos_application(true);

    // Converge healthy with prune: true.
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("initial apply");
    cluster.make_deployment_ready(DEST_NAMESPACE, "api", 1);
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("steady-state healthy");

    let expected_keys: BTreeSet<String> = [
        format!("/ConfigMap/{DEST_NAMESPACE}/cm-a"),
        format!("/ConfigMap/{DEST_NAMESPACE}/cm-b"),
        format!("apps/Deployment/{DEST_NAMESPACE}/api"),
    ]
    .into_iter()
    .collect();
    assert_eq!(cluster.object_keys(), expected_keys);

    // Push a commit with broken YAML so rendering fails with ManifestError!
    git.add_commit(
        "main",
        [(
            "manifests/broken.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: [unclosed-bracket\n",
        )],
    );

    let (err, class, delay) = controller
        .reconcile(&app, &cluster)
        .await
        .pipe_err_unreachable();
    assert!(
        matches!(*err, ReconcileError::Manifest(_)),
        "broken YAML must fail with ManifestError, got: {err:?}"
    );
    assert_eq!(class, FailureClass::Terminal);
    assert_eq!(
        delay,
        ferriscd_controller::controller::TERMINAL_DELAY,
        "terminal manifest error must use TERMINAL_DELAY, not spin retry queue"
    );

    let failed_status = cluster.status().expect("status patched on render failure");
    assert_ready_status(&failed_status, ConditionStatus::False, "render failure");
    // TRAP GUARD T15.4: ZERO resources may be pruned when rendering fails!
    assert!(
        cluster.delete_calls().is_empty(),
        "TRAP GUARD T15.4 VIOLATION: delete called on renderer failure: {:?}",
        cluster.delete_calls()
    );
    assert_eq!(
        cluster.object_keys(),
        expected_keys,
        "all live objects must survive a broken-manifest commit"
    );
    assert_eq!(
        inventory_key_set(&failed_status),
        expected_keys,
        "status.inventory must remain untouched on renderer failure"
    );

    // Fix the commit and verify clean recovery.
    git.add_commit(
        "main",
        [
            (
                "manifests/cm-a.yaml",
                configmap_yaml("cm-a", "v2-fixed", None),
            ),
            ("manifests/cm-b.yaml", configmap_yaml("cm-b", "v1", None)),
            (
                "manifests/deploy.yaml",
                deployment_yaml("api", "3.10", None),
            ),
        ],
    );
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("apply after fix");
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("steady-state after fix");

    let recovered = cluster.status().expect("recovered status");
    assert_ready_status(&recovered, ConditionStatus::True, "recovered after fix");
    assert_eq!(
        recovered.sync.as_ref().map(|s| s.status),
        Some(SyncStatus::Synced)
    );
    assert_eq!(
        cluster.live_data_value(&format!("/ConfigMap/{DEST_NAMESPACE}/cm-a"), "key"),
        Some("v2-fixed".to_owned())
    );
    assert!(cluster.delete_calls().is_empty());
}

#[tokio::test]
async fn chaos_hermetic_empty_render_over_nonempty_inventory_refuses_mass_prune() {
    // Defense-in-depth for Trap Guard T15.4: even if a broken template or wrong path yields 0
    // manifests without a YAML parse error, FerrisCD must refuse to wipe a non-empty inventory
    // unless `FERRISCD_ALLOW_EMPTY_DESIRED` is explicitly enabled.
    let git = Arc::new(FakeGitClient::with_config(
        FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::Production),
    ));
    git.add_commit(
        "main",
        [
            ("manifests/cm-a.yaml", configmap_yaml("cm-a", "v1", None)),
            ("manifests/cm-b.yaml", configmap_yaml("cm-b", "v1", None)),
        ],
    );

    let cluster = ChaosCluster::new_with_namespace(DEST_NAMESPACE);
    let controller = ControllerRuntime::boot(git.clone(), cluster.clone());
    let app = chaos_application(true);

    controller
        .reconcile(&app, &cluster)
        .await
        .expect("initial apply");
    controller.reconcile(&app, &cluster).await.expect("synced");

    let expected_keys: BTreeSet<String> = [
        format!("/ConfigMap/{DEST_NAMESPACE}/cm-a"),
        format!("/ConfigMap/{DEST_NAMESPACE}/cm-b"),
    ]
    .into_iter()
    .collect();
    assert_eq!(cluster.object_keys(), expected_keys);

    // Push a commit where `manifests/` has only a non-YAML readme (renders 0 Kubernetes resources).
    git.add_commit("main", [("manifests/README.md", "# empty render\n")]);

    let (err, _class, _delay) = controller
        .reconcile(&app, &cluster)
        .await
        .pipe_err_unreachable();
    assert!(
        err.to_string().contains("zero")
            || err.to_string().contains("empty")
            || matches!(
                *err,
                ReconcileError::Invalid { .. } | ReconcileError::Manifest(_)
            ),
        "empty desired set over non-empty inventory must be refused, got: {err:?}"
    );
    assert!(
        cluster.delete_calls().is_empty(),
        "empty render must NEVER mass-prune live resources"
    );
    assert_eq!(
        cluster.object_keys(),
        expected_keys,
        "all live resources must survive an empty render"
    );
    let st = cluster.status().expect("status patched");
    assert_ready_status(&st, ConditionStatus::False, "empty render refused");
    assert_eq!(
        inventory_key_set(&st),
        expected_keys,
        "status.inventory must remain untouched when empty render is refused"
    );
}

// ===========================================================================
// Scenario 3 (Hermetic): Transient K8s API Failures (429 / 503) & Backoff
// ===========================================================================

#[tokio::test]
async fn chaos_hermetic_k8s_api_rate_limit_and_503_backoff_and_recovery() {
    let git = Arc::new(FakeGitClient::with_config(
        FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::Production),
    ));
    git.add_commit(
        "main",
        [
            ("manifests/cfg-a.yaml", configmap_yaml("cfg-a", "v1", None)),
            ("manifests/cfg-b.yaml", configmap_yaml("cfg-b", "v1", None)),
            ("manifests/web.yaml", deployment_yaml("web", "3.10", None)),
        ],
    );

    let cluster = ChaosCluster::new_with_namespace(DEST_NAMESPACE);
    let controller = ControllerRuntime::boot(git.clone(), cluster.clone());
    let app = chaos_application(true);

    // Step 1: Converge initial state.
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("initial apply");
    cluster.make_deployment_ready(DEST_NAMESPACE, "web", 1);
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("initial healthy");
    assert_eq!(cluster.object_keys().len(), 3);

    // Step 2: Push a new commit updating cfg-a, cfg-b and adding cfg-c.
    git.add_commit(
        "main",
        [
            ("manifests/cfg-a.yaml", configmap_yaml("cfg-a", "v2", None)),
            ("manifests/cfg-b.yaml", configmap_yaml("cfg-b", "v2", None)),
            ("manifests/cfg-c.yaml", configmap_yaml("cfg-c", "v2", None)),
            ("manifests/web.yaml", deployment_yaml("web", "3.10", None)),
        ],
    );

    // Step 3: Inject 7 consecutive transient K8s API failures spanning live GET, dry-run, and
    // SSA apply (429 TooManyRequests & 503 ServiceUnavailable), verifying exponential doubling all
    // the way to saturation at `RETRY_MAX_DELAY` (180s):
    //   attempt 0 ->   5s (Live GET 429)
    //   attempt 1 ->  10s (Live GET 503)
    //   attempt 2 ->  20s (DryRun 429)
    //   attempt 3 ->  40s (DryRun 503)
    //   attempt 4 ->  80s (Apply 429 on cfg-b -> PartialSync)
    //   attempt 5 -> 160s (Apply 503 on cfg-b -> PartialSync)
    //   attempt 6 -> 180s (Apply 429 on cfg-b -> saturated at RETRY_MAX_DELAY!)
    let cfg_b_key = format!("/ConfigMap/{DEST_NAMESPACE}/cfg-b");

    cluster.push_live_get_fault(LiveStateError::Api {
        resource: format!("/ConfigMap/{DEST_NAMESPACE}/cfg-a"),
        code: 429,
        message: "TooManyRequests: API priority & fairness rate limit".to_owned(),
    });
    cluster.push_live_get_fault(LiveStateError::Api {
        resource: format!("/ConfigMap/{DEST_NAMESPACE}/cfg-a"),
        code: 503,
        message: "ServiceUnavailable: apiserver restarting".to_owned(),
    });
    cluster.push_dry_run_fault(DryRunError::Api {
        resource: format!("/ConfigMap/{DEST_NAMESPACE}/cfg-a"),
        code: 429,
        message: "TooManyRequests during dryRun=All".to_owned(),
    });
    cluster.push_dry_run_fault(DryRunError::Api {
        resource: format!("/ConfigMap/{DEST_NAMESPACE}/cfg-a"),
        code: 503,
        message: "ServiceUnavailable during dryRun=All".to_owned(),
    });
    cluster.push_apply_fault(
        &cfg_b_key,
        kube_status_error(429, "TooManyRequests", "rate limit exceeded on SSA patch"),
    );
    cluster.push_apply_fault(
        &cfg_b_key,
        kube_status_error(
            503,
            "ServiceUnavailable",
            "etcd leader election in progress",
        ),
    );
    cluster.push_apply_fault(
        &cfg_b_key,
        kube_status_error(429, "TooManyRequests", "still throttled"),
    );

    let expected_backoff = [
        RETRY_BASE_DELAY,      // 5s
        RETRY_BASE_DELAY * 2,  // 10s
        RETRY_BASE_DELAY * 4,  // 20s
        RETRY_BASE_DELAY * 8,  // 40s
        RETRY_BASE_DELAY * 16, // 80s
        RETRY_BASE_DELAY * 32, // 160s
        RETRY_MAX_DELAY,       // 180s (saturated cap!)
    ];

    for (attempt, expected_delay) in expected_backoff.iter().enumerate() {
        let (err, class, delay) = controller
            .reconcile(&app, &cluster)
            .await
            .pipe_err_unreachable();
        assert_eq!(
            class,
            FailureClass::Retryable,
            "attempt {attempt}: 429/503 API error must be Retryable, got {err:?}"
        );
        assert_eq!(
            delay, *expected_delay,
            "attempt {attempt}: backoff sequence must double and cap at RETRY_MAX_DELAY"
        );
        match attempt {
            0 | 1 => assert!(matches!(*err, ReconcileError::Live(_)), "got {err:?}"),
            2 | 3 => assert!(matches!(*err, ReconcileError::Diff(_)), "got {err:?}"),
            4..=6 => assert!(
                matches!(*err, ReconcileError::PartialSync { .. }),
                "got {err:?}"
            ),
            _ => unreachable!(),
        }

        let st = cluster.status().expect("status patched on API error");
        assert_ready_status(&st, ConditionStatus::False, "during K8s API outage");
        assert!(
            cluster.delete_calls().is_empty(),
            "zero resources may be pruned during K8s API errors (attempt {attempt})"
        );
    }

    // Verify Prometheus metrics reflect exact retryable counts and zero leaked in-flight gauges!
    let scraped = controller
        .metrics
        .encode()
        .expect("encode prometheus metrics");
    assert_eq!(
        parse_prometheus_sample(&scraped, "ferriscd_reconcile_total{result=\"retryable\"}"),
        Some(7.0),
        "all 7 transient API failures must be recorded under result=\"retryable\":\n{scraped}"
    );
    assert_eq!(
        parse_prometheus_sample(&scraped, "ferriscd_active_reconciles"),
        Some(0.0),
        "active_reconciles gauge must return to 0 after failed passes:\n{scraped}"
    );

    // Step 4: Faults are exhausted -> next reconcile converges cleanly and resets backoff!
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("apply recovery pass");
    controller
        .reconcile(&app, &cluster)
        .await
        .expect("steady-state convergence");

    let final_status = cluster.status().expect("final status");
    assert_ready_status(
        &final_status,
        ConditionStatus::True,
        "post-API-fault recovery",
    );
    assert_eq!(
        final_status.sync.as_ref().map(|s| s.status),
        Some(SyncStatus::Synced)
    );
    assert_eq!(
        final_status.health.as_ref().map(|h| h.status),
        Some(HealthStatus::Healthy)
    );
    assert_eq!(
        controller.backoff.attempts(&object_key(&app)),
        0,
        "backoff attempts must reset to 0 after clean recovery"
    );
    assert_eq!(
        cluster.live_data_value(&format!("/ConfigMap/{DEST_NAMESPACE}/cfg-a"), "key"),
        Some("v2".to_owned())
    );
    assert_eq!(
        cluster.live_data_value(&format!("/ConfigMap/{DEST_NAMESPACE}/cfg-b"), "key"),
        Some("v2".to_owned())
    );
    assert_eq!(
        cluster.live_data_value(&format!("/ConfigMap/{DEST_NAMESPACE}/cfg-c"), "key"),
        Some("v2".to_owned())
    );
    let expected_keys: BTreeSet<String> = [
        format!("/ConfigMap/{DEST_NAMESPACE}/cfg-a"),
        format!("/ConfigMap/{DEST_NAMESPACE}/cfg-b"),
        format!("/ConfigMap/{DEST_NAMESPACE}/cfg-c"),
        format!("apps/Deployment/{DEST_NAMESPACE}/web"),
    ]
    .into_iter()
    .collect();
    assert_eq!(inventory_key_set(&final_status), expected_keys);
    assert_eq!(cluster.object_keys(), expected_keys);
    assert!(cluster.delete_calls().is_empty());
    assert!(
        cluster.status_patch_count() >= 11,
        "every pass (initial, 7 failed, recovery) must patch /status"
    );
}

/// Fast, deterministic verification that our loopback `LocalGitTcpServer` + `ssh` transport
/// fixture exercised by live Scenario 2 produces a genuine retryable [`RepoError::Network`]
/// (`is_retryable() == true` -> `FailureClass::Retryable`, NOT `Terminal` 600s delay) during an
/// outage and recovers cleanly on restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chaos_local_git_tcp_server_outage_produces_retryable_network_error_and_recovers() {
    let fixture = tempfile::tempdir().expect("create temp git fixture dir");
    let work_repo = fixture.path().join("work");
    let bare_repo = fixture.path().join("origin.git");
    std::fs::create_dir_all(&work_repo).expect("create work repo dir");
    write_file(&work_repo, "cm.yaml", &configmap_yaml("net-a", "v1", None));
    git_init_and_commit(&work_repo);
    git_cmd(
        fixture.path(),
        &[
            "clone",
            "--bare",
            &work_repo.display().to_string(),
            &bare_repo.display().to_string(),
        ],
    );

    let bin_dir = fixture.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create ssh shim dir");
    let ssh_shim = write_ssh_tcp_shim(&bin_dir);

    let mut server = LocalGitTcpServer::start(bare_repo.clone()).await;
    let repo_url = server.ssh_url();
    let creds = fixture_ssh_credentials(server.addr().port());

    let work_root = fixture.path().join("gix-work");
    let client = GixGitClient::new(
        GixGitClientConfig::new()
            .with_url_policy(RepoUrlPolicy::Production)
            .with_work_root(&work_root)
            .with_ssh_program(&ssh_shim),
    );
    let src = GitSource::new(&repo_url, "main", ".");

    // 1. Healthy fetch + checkout over real loopback TCP transport succeeds.
    let rev1 = client
        .resolve_revision(&src, &creds)
        .await
        .expect("initial resolve_revision over LocalGitTcpServer must succeed");
    let co1 = client
        .checkout(&src, &rev1.commit_sha, &creds)
        .await
        .expect("initial checkout over LocalGitTcpServer must succeed");
    assert!(
        std::fs::read_to_string(co1.root_dir().join("cm.yaml"))
            .expect("read cm.yaml")
            .contains("v1"),
        "checked-out tree must contain v1"
    );

    // 2. Stop the Git server -> connection refused MUST classify as Retryable `RepoError::Network`.
    server.stop().await;
    let outage_err = client
        .resolve_revision(&src, &creds)
        .await
        .expect_err("stopped LocalGitTcpServer must fail resolve_revision");
    assert!(
        matches!(outage_err, RepoError::Network { .. }),
        "live Git outage must classify as RepoError::Network (not Terminal RepositoryError), got: {outage_err:?}"
    );
    assert!(
        outage_err.is_retryable(),
        "live Git outage must be retryable (FailureClass::Retryable), got: {outage_err:?}"
    );

    // 3. Restart on the same port and push v2 -> automatic recovery succeeds immediately.
    server.restart().await;
    write_file(
        &work_repo,
        "cm.yaml",
        &configmap_yaml("net-a", "v2-recovered", None),
    );
    git_commit(&work_repo, "post-outage commit");
    git_cmd(
        &work_repo,
        &["push", &bare_repo.display().to_string(), "main"],
    );

    let rev2 = client
        .resolve_revision(&src, &creds)
        .await
        .expect("resolve_revision must recover after LocalGitTcpServer restart");
    assert_ne!(rev2.commit_sha, rev1.commit_sha);
    let co2 = client
        .checkout(&src, &rev2.commit_sha, &creds)
        .await
        .expect("checkout must recover after LocalGitTcpServer restart");
    assert!(
        std::fs::read_to_string(co2.root_dir().join("cm.yaml"))
            .expect("read cm.yaml")
            .contains("v2-recovered"),
        "recovered checkout must contain v2-recovered"
    );
}

// ===========================================================================
// Live `kind` Chaos Suite (`#[ignore]` + Mandatory `kind-` Safety Guard)
// ===========================================================================

/// Safety guard (AGENTS.md): refuses to touch any non-`kind` Kubernetes context.
fn assert_kind_context() -> String {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "SAFETY GUARD: refusing to run live chaos test against non-kind cluster context '{context}' \
         (must start with 'kind-')"
    );
    context
}

/// Scenario 1 (Live `kind`): `SIGKILL` a real `ferriscd controller` child process mid-multi-wave
/// sync, restart a fresh controller process, and assert clean convergence with zero orphaned or
/// corrupted inventory entries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn live_kind_chaos_sigkill_controller_mid_multi_wave_sync() {
    assert_kind_context();
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let app_name = "chaos-sigkill-waves";
    let target_ns = "ferriscd-chaos-sigkill";
    let _cleanup = LiveChaosCleanup::new(app_name, target_ns);

    let fixture = tempfile::tempdir().expect("create temp git repo dir");
    let repo = fixture.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create repo dir");
    write_file(
        &repo,
        "w0-cm.yaml",
        &configmap_yaml("chaos-w0", "v1", Some(0)),
    );
    write_file(
        &repo,
        "w0-deploy.yaml",
        &deployment_yaml("chaos-w0-deploy", "3.10", Some(0)),
    );
    write_file(
        &repo,
        "w1-cm.yaml",
        &configmap_yaml("chaos-w1", "v1", Some(1)),
    );
    write_file(
        &repo,
        "w1-deploy.yaml",
        &deployment_yaml("chaos-w1-deploy", "3.10", Some(1)),
    );
    write_file(
        &repo,
        "w2-cm.yaml",
        &configmap_yaml("chaos-w2", "v1", Some(2)),
    );
    git_init_and_commit(&repo);

    let work_1 = tempfile::tempdir().expect("work_root 1");
    let mut ctrl_1 = LiveControllerProcess::start(work_1.path(), None, &[]);

    apply_live_application(app_name, target_ns, &repo.display().to_string(), true, 5);

    // Wait until Wave 0 has landed AND multi-wave operation is actively `Running` (mid-sync!).
    wait_for_condition(
        Duration::from_secs(180),
        "Wave 0 ConfigMap to land and operationState.phase == Running",
        move || {
            live_object_exists("configmap", "chaos-w0", target_ns)
                && app_jsonpath(app_name, "{.status.operationState.phase}") == "Running"
        },
    )
    .await;

    // Send real SIGKILL (`kill -9` on Unix) mid-multi-wave sync!
    ctrl_1.sigkill();

    // Boot a brand-new controller process with a fresh work_root against the same cluster.
    let work_2 = tempfile::tempdir().expect("work_root 2");
    let _ctrl_2 = LiveControllerProcess::start(work_2.path(), None, &[]);

    wait_for_condition(
        Duration::from_secs(240),
        "restarted controller to converge all 3 waves to Synced + Healthy + Succeeded",
        move || {
            app_jsonpath(app_name, "{.status.sync.status}") == "Synced"
                && app_jsonpath(app_name, "{.status.health.status}") == "Healthy"
                && app_jsonpath(app_name, "{.status.operationState.phase}") == "Succeeded"
                && app_ready_status(app_name).as_deref() == Some("True")
        },
    )
    .await;

    let expected_inventory: BTreeSet<String> = [
        format!("/ConfigMap/{target_ns}/chaos-w0"),
        format!("apps/Deployment/{target_ns}/chaos-w0-deploy"),
        format!("/ConfigMap/{target_ns}/chaos-w1"),
        format!("apps/Deployment/{target_ns}/chaos-w1-deploy"),
        format!("/ConfigMap/{target_ns}/chaos-w2"),
    ]
    .into_iter()
    .collect();
    let observed_raw: Vec<String> = app_jsonpath(app_name, "{.status.inventory[*].key}")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        observed_raw.len(),
        expected_inventory.len(),
        "zero duplicate or corrupted inventory entries allowed after SIGKILL: {observed_raw:?}"
    );
    let observed_set: BTreeSet<String> = observed_raw.into_iter().collect();
    assert_eq!(observed_set, expected_inventory);

    for (kind, name) in [
        ("configmap", "chaos-w0"),
        ("deployment", "chaos-w0-deploy"),
        ("configmap", "chaos-w1"),
        ("deployment", "chaos-w1-deploy"),
        ("configmap", "chaos-w2"),
    ] {
        assert!(
            live_object_exists(kind, name, target_ns),
            "{kind}/{name} must exist in {target_ns} after SIGKILL recovery"
        );
    }
}

/// Scenario 2 (Live `kind`): Take down the local Git server (real loopback TCP transport
/// triggering `ConnectionRefused` -> `RepoError::Network` -> `FailureClass::Retryable`) for 90s
/// (overridable via `FERRISCD_CHAOS_GIT_OUTAGE_SECONDS`) while workloads are healthy with
/// `prune: true`, assert `Ready=False`, stable `status.inventory`, and unchanged workload UIDs
/// (**ZERO** workloads pruned or recreated), then restart the Git server and assert automatic
/// recovery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn live_kind_chaos_git_outage_never_prunes_and_recovers() {
    assert_kind_context();
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let outage_secs: u64 = std::env::var("FERRISCD_CHAOS_GIT_OUTAGE_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(90);

    let app_name = "chaos-git-outage";
    let target_ns = "ferriscd-chaos-git-outage";
    let secret_name = "chaos-git-outage-repo-creds";
    let _cleanup = LiveChaosCleanup::with_secret(app_name, target_ns, secret_name);

    let fixture = tempfile::tempdir().expect("create temp git dir");
    let work_repo = fixture.path().join("work");
    let bare_repo = fixture.path().join("origin.git");
    std::fs::create_dir_all(&work_repo).expect("create work repo dir");

    write_file(
        &work_repo,
        "cm-a.yaml",
        &configmap_yaml("outage-a", "v1", None),
    );
    write_file(
        &work_repo,
        "cm-b.yaml",
        &configmap_yaml("outage-b", "v1", None),
    );
    write_file(
        &work_repo,
        "deploy.yaml",
        &deployment_yaml("outage-web", "3.10", None),
    );
    git_init_and_commit(&work_repo);
    git_cmd(
        fixture.path(),
        &[
            "clone",
            "--bare",
            &work_repo.display().to_string(),
            &bare_repo.display().to_string(),
        ],
    );

    // Serve the bare repository over a real loopback TCP transport (`ssh://git@127.0.0.1:<port>/repo.git`)
    // backed by `LocalGitTcpServer` + a control-plane `ferriscd.io/secret-type=repository` Secret.
    // Stopping the listener yields real OS `ConnectionRefused` -> `RepoError::Network` ->
    // `FailureClass::Retryable` (exponential backoff, not 600s terminal delay).
    let bin_dir = fixture.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create ssh shim dir");
    let _ssh_shim = write_ssh_tcp_shim(&bin_dir);
    let mut git_server = LocalGitTcpServer::start(bare_repo.clone()).await;
    let repo_url = git_server.ssh_url();
    apply_live_ssh_repo_secret(secret_name, &repo_url, git_server.addr().port());

    let prepended_path = match std::env::var("PATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", bin_dir.display()),
        _ => bin_dir.display().to_string(),
    };
    let ctrl_work = tempfile::tempdir().expect("controller work_root");
    let _ctrl = LiveControllerProcess::start(ctrl_work.path(), None, &[("PATH", prepended_path)]);

    // Enable `prune: true` + short `requeueAfterSeconds: 5` so the outage exercises multiple
    // consecutive retryable failed reconciles during the outage window.
    apply_live_application(app_name, target_ns, &repo_url, true, 5);

    wait_for_condition(
        Duration::from_secs(180),
        "initial convergence to Synced + Healthy",
        move || {
            app_jsonpath(app_name, "{.status.sync.status}") == "Synced"
                && app_jsonpath(app_name, "{.status.health.status}") == "Healthy"
                && app_ready_status(app_name).as_deref() == Some("True")
        },
    )
    .await;

    // Capture baseline workload UIDs and `status.inventory` keys to prove workloads are NEVER
    // pruned or recreated during the outage or across recovery.
    let expected_inventory: BTreeSet<String> = [
        format!("/ConfigMap/{target_ns}/outage-a"),
        format!("/ConfigMap/{target_ns}/outage-b"),
        format!("apps/Deployment/{target_ns}/outage-web"),
    ]
    .into_iter()
    .collect();
    let (uid_a, uid_b, uid_web, initial_inventory) = tokio::task::spawn_blocking(move || {
        (
            live_object_uid("configmap", "outage-a", target_ns)
                .expect("outage-a UID after initial convergence"),
            live_object_uid("configmap", "outage-b", target_ns)
                .expect("outage-b UID after initial convergence"),
            live_object_uid("deployment", "outage-web", target_ns)
                .expect("outage-web UID after initial convergence"),
            app_inventory_key_set(app_name),
        )
    })
    .await
    .expect("capture baseline UIDs & inventory");
    assert_eq!(
        initial_inventory, expected_inventory,
        "initial status.inventory must track all 3 workloads"
    );

    // Take down the local Git TCP server for `outage_secs` (default 90s).
    git_server.stop().await;

    // Verify controller detects the retryable network outage and patches Ready=False.
    wait_for_condition(
        Duration::from_secs(60),
        "Ready=False during Git outage",
        move || app_ready_status(app_name).as_deref() == Some("False"),
    )
    .await;

    // Hold outage for the configured duration, periodically asserting ZERO workloads are pruned
    // or recreated (exact UID + `status.inventory` stability).
    let outage_deadline = Instant::now() + Duration::from_secs(outage_secs);
    while Instant::now() < outage_deadline {
        let expected_uid_a = uid_a.clone();
        let expected_uid_b = uid_b.clone();
        let expected_uid_web = uid_web.clone();
        let expected_inv = initial_inventory.clone();
        tokio::task::spawn_blocking(move || {
            assert_eq!(
                live_object_uid("configmap", "outage-a", target_ns).as_deref(),
                Some(expected_uid_a.as_str()),
                "TRAP GUARD T15.4: outage-a was pruned or recreated during Git outage"
            );
            assert_eq!(
                live_object_uid("configmap", "outage-b", target_ns).as_deref(),
                Some(expected_uid_b.as_str()),
                "TRAP GUARD T15.4: outage-b was pruned or recreated during Git outage"
            );
            assert_eq!(
                live_object_uid("deployment", "outage-web", target_ns).as_deref(),
                Some(expected_uid_web.as_str()),
                "TRAP GUARD T15.4: outage-web was pruned or recreated during Git outage"
            );
            assert_eq!(
                app_inventory_key_set(app_name),
                expected_inv,
                "TRAP GUARD T15.4: status.inventory changed during Git outage"
            );
        })
        .await
        .expect("outage stability check task panicked");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Restart the Git server on the same port and push a new commit to prove automatic recovery
    // under retryable exponential backoff.
    write_file(
        &work_repo,
        "cm-a.yaml",
        &configmap_yaml("outage-a", "v2-recovered", None),
    );
    git_commit(&work_repo, "post-outage update");
    git_cmd(
        &work_repo,
        &["push", &bare_repo.display().to_string(), "main"],
    );
    git_server.restart().await;

    wait_for_condition(
        Duration::from_secs(240),
        "automatic recovery to Ready=True + Synced + Healthy with v2-recovered",
        move || {
            app_ready_status(app_name).as_deref() == Some("True")
                && app_jsonpath(app_name, "{.status.sync.status}") == "Synced"
                && app_jsonpath(app_name, "{.status.health.status}") == "Healthy"
                && live_configmap_key(target_ns, "outage-a").as_deref() == Some("v2-recovered")
        },
    )
    .await;

    // Confirm post-recovery UIDs and `status.inventory` still match baseline (in-place SSA update,
    // zero workloads pruned or recreated).
    let (post_uid_a, post_uid_b, post_uid_web, post_inventory) =
        tokio::task::spawn_blocking(move || {
            (
                live_object_uid("configmap", "outage-a", target_ns),
                live_object_uid("configmap", "outage-b", target_ns),
                live_object_uid("deployment", "outage-web", target_ns),
                app_inventory_key_set(app_name),
            )
        })
        .await
        .expect("capture post-recovery UIDs & inventory");
    assert_eq!(
        post_uid_a.as_deref(),
        Some(uid_a.as_str()),
        "outage-a UID must remain stable across outage and SSA recovery"
    );
    assert_eq!(
        post_uid_b.as_deref(),
        Some(uid_b.as_str()),
        "outage-b UID must remain stable across outage and recovery"
    );
    assert_eq!(
        post_uid_web.as_deref(),
        Some(uid_web.as_str()),
        "outage-web UID must remain stable across outage and recovery"
    );
    assert_eq!(
        post_inventory, initial_inventory,
        "status.inventory must remain identical after recovery"
    );
}

/// Scenario 3 (Live `kind`): Place a local TCP fault-injecting proxy in front of the `kind` API
/// server (preserving full mTLS SAN validation on `127.0.0.1`), inject transient API drops while
/// updating an `Application`, verify backoff, stable `status.inventory`, and unchanged workload
/// UIDs, clear the fault, and assert clean convergence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn live_kind_chaos_k8s_api_fault_proxy_backoff_and_recovery() {
    let context = assert_kind_context();
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let app_name = "chaos-api-fault";
    let target_ns = "ferriscd-chaos-api-fault";
    let _cleanup = LiveChaosCleanup::new(app_name, target_ns);

    // Extract the `kind-*` API server address (`https://127.0.0.1:<port>`) and spin up a local
    // TCP passthrough proxy on `127.0.0.1:<ephemeral>` so we can toggle transient API faults on
    // and off without altering TLS certificates (kind's apiserver cert includes IP SAN 127.0.0.1).
    let raw_kubeconfig =
        kubectl_stdout(&["config", "view", "--raw", "--minify", "--context", &context]);
    let upstream_addr = extract_loopback_server_addr(&raw_kubeconfig);
    let proxy = TcpFaultProxy::start(upstream_addr).await;

    let temp = tempfile::tempdir().expect("temp dir for proxy kubeconfig + repo");
    let proxy_kubeconfig_path = temp.path().join("kubeconfig-proxy.yaml");
    let rewritten_kubeconfig = raw_kubeconfig.replace(
        &format!("https://{upstream_addr}"),
        &format!("https://{}", proxy.listen_addr()),
    );
    assert!(
        rewritten_kubeconfig.contains(&proxy.listen_addr().to_string()),
        "rewritten kubeconfig must point at local TCP fault proxy {}",
        proxy.listen_addr()
    );
    std::fs::write(&proxy_kubeconfig_path, rewritten_kubeconfig).expect("write proxy kubeconfig");

    let repo = temp.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create repo dir");
    write_file(&repo, "cm-a.yaml", &configmap_yaml("api-a", "v1", None));
    write_file(&repo, "cm-b.yaml", &configmap_yaml("api-b", "v1", None));
    git_init_and_commit(&repo);

    let ctrl_work = temp.path().join("work");
    std::fs::create_dir_all(&ctrl_work).expect("create work_root");
    let _ctrl = LiveControllerProcess::start(&ctrl_work, Some(&proxy_kubeconfig_path), &[]);

    apply_live_application(app_name, target_ns, &repo.display().to_string(), true, 5);

    wait_for_condition(
        Duration::from_secs(180),
        "initial sync through proxy",
        move || {
            app_jsonpath(app_name, "{.status.sync.status}") == "Synced"
                && live_configmap_key(target_ns, "api-a").as_deref() == Some("v1")
        },
    )
    .await;

    // Capture baseline workload UIDs and `status.inventory` key set after initial convergence.
    let expected_inventory: BTreeSet<String> = [
        format!("/ConfigMap/{target_ns}/api-a"),
        format!("/ConfigMap/{target_ns}/api-b"),
    ]
    .into_iter()
    .collect();
    let (uid_a, uid_b, initial_inventory) = tokio::task::spawn_blocking(move || {
        (
            live_object_uid("configmap", "api-a", target_ns).expect("api-a UID after initial sync"),
            live_object_uid("configmap", "api-b", target_ns).expect("api-b UID after initial sync"),
            app_inventory_key_set(app_name),
        )
    })
    .await
    .expect("capture baseline UIDs & inventory");
    assert_eq!(
        initial_inventory, expected_inventory,
        "initial status.inventory must track both workloads"
    );

    // Toggle transient API failures ON through the proxy while committing a change.
    proxy.set_inject_fault(true);
    write_file(
        &repo,
        "cm-a.yaml",
        &configmap_yaml("api-a", "v2-after-fault", None),
    );
    git_commit(&repo, "update during API outage");

    // Wait until the proxy has actively rejected at least 3 controller connections (proving the
    // fault actually hit the running controller).
    let dropped_counter = proxy.dropped_counter();
    wait_for_condition(
        Duration::from_secs(60),
        "proxy to reject >= 3 controller API connections",
        move || dropped_counter.load(Ordering::SeqCst) >= 3,
    )
    .await;

    // Existing workloads and `status.inventory` must stay untouched during the API fault window.
    let (mid_uid_a, mid_uid_b, mid_inventory) = tokio::task::spawn_blocking(move || {
        (
            live_object_uid("configmap", "api-a", target_ns),
            live_object_uid("configmap", "api-b", target_ns),
            app_inventory_key_set(app_name),
        )
    })
    .await
    .expect("capture mid-fault UIDs & inventory");
    assert_eq!(
        mid_uid_a.as_deref(),
        Some(uid_a.as_str()),
        "api-a must not be pruned or recreated during K8s API failures"
    );
    assert_eq!(
        mid_uid_b.as_deref(),
        Some(uid_b.as_str()),
        "api-b must not be pruned or recreated during K8s API failures"
    );
    assert_eq!(
        mid_inventory, initial_inventory,
        "status.inventory must remain stable during K8s API failures"
    );

    // Clear the API fault and verify exponential-backoff recovery converges `v2-after-fault`.
    proxy.set_inject_fault(false);
    wait_for_condition(
        Duration::from_secs(240),
        "controller to recover from API faults and apply v2-after-fault",
        move || {
            app_ready_status(app_name).as_deref() == Some("True")
                && app_jsonpath(app_name, "{.status.sync.status}") == "Synced"
                && live_configmap_key(target_ns, "api-a").as_deref() == Some("v2-after-fault")
                && live_object_exists("configmap", "api-b", target_ns)
        },
    )
    .await;

    // Post-recovery UIDs and `status.inventory` must remain identical to baseline.
    let (post_uid_a, post_uid_b, post_inventory) = tokio::task::spawn_blocking(move || {
        (
            live_object_uid("configmap", "api-a", target_ns),
            live_object_uid("configmap", "api-b", target_ns),
            app_inventory_key_set(app_name),
        )
    })
    .await
    .expect("capture post-recovery UIDs & inventory");
    assert_eq!(
        post_uid_a.as_deref(),
        Some(uid_a.as_str()),
        "api-a UID must remain stable across K8s API fault and SSA recovery"
    );
    assert_eq!(
        post_uid_b.as_deref(),
        Some(uid_b.as_str()),
        "api-b UID must remain stable across K8s API fault and recovery"
    );
    assert_eq!(
        post_inventory, initial_inventory,
        "status.inventory must remain identical after K8s API fault recovery"
    );
}

// ===========================================================================
// Live `kind` Infrastructure Helpers (Git TCP Server, Proxy, Process, kubectl)
// ===========================================================================

/// Local loopback TCP Git server (`git-upload-pack`) with clean stop/restart on the same port.
///
/// Used by Scenario 2 so stopping the server yields genuine OS `ConnectionRefused` ->
/// `RepoError::Network` -> `FailureClass::Retryable` on both Linux and macOS without relying on
/// `SSL_CERT_FILE` (which Apple `SecTrust` ignores in `rustls-platform-verifier`).
struct LocalGitTcpServer {
    addr: SocketAddr,
    bare_repo: PathBuf,
    cancel: Option<CancellationToken>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LocalGitTcpServer {
    async fn start(bare_repo: PathBuf) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local Git TCP server");
        let addr = listener.local_addr().expect("local Git TCP server addr");
        let (cancel, task) = Self::spawn_accept_loop(listener, bare_repo.clone());
        Self {
            addr,
            bare_repo,
            cancel: Some(cancel),
            task: Some(task),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn ssh_url(&self) -> String {
        format!("ssh://git@127.0.0.1:{}/repo.git", self.addr.port())
    }

    /// Cancels the accept loop and all active connection tasks, dropping the `TcpListener` so
    /// subsequent connects fail immediately with `ConnectionRefused`.
    async fn stop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Re-binds the exact same loopback port (`SO_REUSEADDR`) and resumes serving `git-upload-pack`.
    async fn restart(&mut self) {
        self.stop().await;
        let socket = tokio::net::TcpSocket::new_v4().expect("create IPv4 TCP socket");
        socket
            .set_reuseaddr(true)
            .expect("enable SO_REUSEADDR for Git server restart");
        socket
            .bind(self.addr)
            .unwrap_or_else(|err| panic!("re-bind local Git server on {}: {err}", self.addr));
        let listener = socket
            .listen(128)
            .expect("listen on restarted local Git server");
        let (cancel, task) = Self::spawn_accept_loop(listener, self.bare_repo.clone());
        self.cancel = Some(cancel);
        self.task = Some(task);
    }

    fn spawn_accept_loop(
        listener: tokio::net::TcpListener,
        bare_repo: PathBuf,
    ) -> (CancellationToken, tokio::task::JoinHandle<()>) {
        let cancel = CancellationToken::new();
        let loop_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _peer) = tokio::select! {
                    () = loop_cancel.cancelled() => break,
                    res = listener.accept() => match res {
                        Ok(pair) => pair,
                        Err(_) => break,
                    },
                };
                let conn_cancel = loop_cancel.clone();
                let repo = bare_repo.clone();
                tokio::spawn(async move {
                    let mut child = match tokio::process::Command::new("git-upload-pack")
                        .arg(&repo)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .kill_on_drop(true)
                        .spawn()
                    {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let (mut child_stdin, mut child_stdout) =
                        match (child.stdin.take(), child.stdout.take()) {
                            (Some(i), Some(o)) => (i, o),
                            _ => return,
                        };
                    let (mut tcp_read, mut tcp_write) = stream.into_split();
                    let relay = async {
                        let to_child = async {
                            let _ = tokio::io::copy(&mut tcp_read, &mut child_stdin).await;
                            let _ = child_stdin.shutdown().await;
                        };
                        let from_child = async {
                            let _ = tokio::io::copy(&mut child_stdout, &mut tcp_write).await;
                            let _ = tcp_write.shutdown().await;
                        };
                        let _ = tokio::join!(to_child, from_child);
                        let _ = child.wait().await;
                    };
                    tokio::select! {
                        () = conn_cancel.cancelled() => {}
                        () = relay => {}
                    }
                });
            }
        });
        (cancel, task)
    }
}

impl Drop for LocalGitTcpServer {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

const FIXTURE_SSH_KEY_PEM: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nFERRISCD-CHAOS-FIXTURE-KEY\n-----END OPENSSH PRIVATE KEY-----\n";

fn fixture_known_hosts(port: u16) -> String {
    format!("[127.0.0.1]:{port} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIChaosFixtureHostKey")
}

fn fixture_ssh_credentials(port: u16) -> RepoCredentials {
    RepoCredentials::SshKey {
        private_key_pem: FIXTURE_SSH_KEY_PEM.to_owned(),
        passphrase: None,
        known_hosts: Some(fixture_known_hosts(port)),
    }
}

/// Writes an executable `ssh` shim script into `bin_dir` that tunnels `git-upload-pack` stdio over
/// a real TCP connection to `127.0.0.1:<port>`.
///
/// When `LocalGitTcpServer` is stopped, `socket.create_connection` fails with OS
/// `ConnectionRefusedError`; emitting `"ssh: Could not resolve hostname 127.0.0.1: ..."` causes
/// `gix-transport`'s OpenSSH stderr parser to yield `io::ErrorKind::ConnectionRefused`, which
/// `gix_client.rs` classifies as `RepoError::Network` (`FailureClass::Retryable`).
fn write_ssh_tcp_shim(bin_dir: &Path) -> PathBuf {
    let shim_path = bin_dir.join("ssh");
    let script = r#"#!/usr/bin/env python3
import os
import socket
import sys
import threading

def parse_port(argv):
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "-p" and i + 1 < len(argv):
            return int(argv[i + 1])
        if arg.startswith("-p") and len(arg) > 2 and arg[2:].isdigit():
            return int(arg[2:])
        i += 1
    raise SystemExit("ssh: missing -p <port> argument")

port = parse_port(sys.argv)
try:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    sock.settimeout(None)
except OSError as exc:
    sys.stderr.write(f"ssh: Could not resolve hostname 127.0.0.1: {exc}\n")
    sys.stderr.flush()
    sys.exit(255)

def pump_stdin():
    fd = sys.stdin.buffer.fileno()
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            sock.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

threading.Thread(target=pump_stdin, daemon=True).start()

try:
    while True:
        data = sock.recv(65536)
        if not data:
            break
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
except OSError as exc:
    sys.stderr.write(f"ssh: Could not resolve hostname 127.0.0.1: {exc}\n")
    sys.stderr.flush()
    sys.exit(255)
finally:
    try:
        sock.close()
    except OSError:
        pass
"#;
    std::fs::write(&shim_path, script).expect("write ssh tcp shim");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&shim_path)
            .expect("stat ssh tcp shim")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&shim_path, perms).expect("chmod +x ssh tcp shim");
    }
    shim_path
}

fn apply_live_ssh_repo_secret(secret_name: &str, repo_url: &str, port: u16) {
    let known_hosts = fixture_known_hosts(port);
    let manifest = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {secret_name}
  namespace: {CONTROL_NAMESPACE}
  labels:
    ferriscd.io/secret-type: repository
type: Opaque
stringData:
  url: "{repo_url}"
  sshPrivateKey: |
    -----BEGIN OPENSSH PRIVATE KEY-----
    FERRISCD-CHAOS-FIXTURE-KEY
    -----END OPENSSH PRIVATE KEY-----
  knownHosts: "{known_hosts}"
"#
    );
    let output = kubectl_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying repository credential Secret {secret_name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Local L4 TCP fault-injecting proxy for live `kind` API-server chaos testing.
struct TcpFaultProxy {
    listen_addr: SocketAddr,
    inject_fault: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl TcpFaultProxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local TCP fault proxy");
        let listen_addr = listener.local_addr().expect("proxy local_addr");
        let inject_fault = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();

        let fault_flag = inject_fault.clone();
        let dropped_counter = dropped.clone();
        let loop_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut inbound, _peer) = tokio::select! {
                    () = loop_cancel.cancelled() => break,
                    res = listener.accept() => match res {
                        Ok(pair) => pair,
                        Err(_) => break,
                    },
                };
                if fault_flag.load(Ordering::SeqCst) {
                    dropped_counter.fetch_add(1, Ordering::SeqCst);
                    drop(inbound);
                    continue;
                }
                let fault_inner = fault_flag.clone();
                let dropped_inner = dropped_counter.clone();
                let conn_cancel = loop_cancel.clone();
                tokio::spawn(async move {
                    let outbound = tokio::select! {
                        () = conn_cancel.cancelled() => return,
                        res = tokio::net::TcpStream::connect(upstream) => match res {
                            Ok(s) => s,
                            Err(_) => return,
                        },
                    };
                    let mut outbound = outbound;
                    let copy = tokio::io::copy_bidirectional(&mut inbound, &mut outbound);
                    let watcher = async {
                        while !fault_inner.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        dropped_inner.fetch_add(1, Ordering::SeqCst);
                    };
                    tokio::select! {
                        () = conn_cancel.cancelled() => {}
                        _ = copy => {}
                        () = watcher => {}
                    }
                });
            }
        });

        Self {
            listen_addr,
            inject_fault,
            dropped,
            cancel,
            task,
        }
    }

    fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    fn set_inject_fault(&self, enabled: bool) {
        self.inject_fault.store(enabled, Ordering::SeqCst);
    }

    fn dropped_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.dropped)
    }
}

impl Drop for TcpFaultProxy {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

/// Manages a real `ferriscd controller` child process for live `kind` chaos tests.
struct LiveControllerProcess {
    child: Option<Child>,
}

impl LiveControllerProcess {
    fn start(work_root: &Path, kubeconfig: Option<&Path>, extra_env: &[(&str, String)]) -> Self {
        let bin = resolve_ferriscd_binary();
        let mut cmd = Command::new(bin);
        cmd.args([
            "controller",
            "--namespace",
            CONTROL_NAMESPACE,
            "--allow-local-repos",
            "--work-root",
            &work_root.display().to_string(),
            "--metrics-addr",
            "127.0.0.1:0",
        ])
        .env("RUST_LOG", "info")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
        if let Some(kc) = kubeconfig {
            cmd.env("KUBECONFIG", kc);
        }
        for (key, val) in extra_env {
            cmd.env(key, val);
        }
        let child = cmd.spawn().expect("spawn ferriscd controller binary");
        Self { child: Some(child) }
    }

    /// Sends `SIGKILL` (`kill -9` on Unix) and reaps the terminated process.
    fn sigkill(&mut self) {
        if let Some(mut child) = self.child.take() {
            child.kill().expect("SIGKILL ferriscd controller process");
            let status = child.wait().expect("reap SIGKILLed controller process");
            assert!(
                !status.success(),
                "SIGKILLed controller must not exit cleanly with status 0"
            );
        }
    }
}

impl Drop for LiveControllerProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn resolve_ferriscd_binary() -> PathBuf {
    if let Ok(explicit) = std::env::var("FERRISCD_BIN") {
        return PathBuf::from(explicit);
    }
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    let debug_bin = workspace_root.join("target/debug/ferriscd");
    if debug_bin.is_file() {
        return debug_bin;
    }
    let release_bin = workspace_root.join("target/release/ferriscd");
    if release_bin.is_file() {
        return release_bin;
    }
    let build = Command::new("cargo")
        .args(["build", "--bin", "ferriscd"])
        .current_dir(&workspace_root)
        .status()
        .expect("cargo build --bin ferriscd");
    assert!(build.success(), "cargo build --bin ferriscd failed");
    debug_bin
}

struct LiveChaosCleanup {
    app_name: String,
    target_ns: String,
    secret_name: Option<String>,
}

impl LiveChaosCleanup {
    fn new(app_name: &str, target_ns: &str) -> Self {
        let this = Self {
            app_name: app_name.to_owned(),
            target_ns: target_ns.to_owned(),
            secret_name: None,
        };
        this.delete_all();
        this
    }

    fn with_secret(app_name: &str, target_ns: &str, secret_name: &str) -> Self {
        let this = Self {
            app_name: app_name.to_owned(),
            target_ns: target_ns.to_owned(),
            secret_name: Some(secret_name.to_owned()),
        };
        this.delete_all();
        this
    }

    fn delete_all(&self) {
        // Delete non-blocking and strip any remaining finalizers so cleanup NEVER hangs 120s or
        // wedges Applications in `Terminating` when the controller was already killed or a test
        // panicked mid-fault.
        let _ = kubectl(&[
            "delete",
            "application",
            &self.app_name,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
            "--wait=false",
        ]);
        let _ = kubectl(&[
            "patch",
            "application",
            &self.app_name,
            "-n",
            CONTROL_NAMESPACE,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":null}}"#,
        ]);
        if let Some(secret_name) = &self.secret_name {
            let _ = kubectl(&[
                "delete",
                "secret",
                secret_name,
                "-n",
                CONTROL_NAMESPACE,
                "--ignore-not-found=true",
                "--wait=false",
            ]);
        }
        let _ = kubectl(&[
            "delete",
            "namespace",
            &self.target_ns,
            "--ignore-not-found=true",
            "--timeout=120s",
        ]);
    }
}

impl Drop for LiveChaosCleanup {
    fn drop(&mut self) {
        self.delete_all();
    }
}

fn extract_loopback_server_addr(kubeconfig_yaml: &str) -> SocketAddr {
    for line in kubeconfig_yaml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("server:") {
            let url = rest.trim().trim_matches('"').trim_matches('\'');
            if let Some(host_port) = url.strip_prefix("https://") {
                let host_port = host_port.trim_end_matches('/');
                if let Ok(addr) = host_port.parse::<SocketAddr>() {
                    return addr;
                }
            }
        }
    }
    panic!("could not extract https://127.0.0.1:<port> API server address from kind kubeconfig");
}

async fn wait_for_condition<F>(timeout: Duration, description: &str, predicate: F)
where
    F: Fn() -> bool + Send + Sync + 'static,
{
    let predicate = Arc::new(predicate);
    let deadline = Instant::now() + timeout;
    loop {
        let check = Arc::clone(&predicate);
        let satisfied = tokio::task::spawn_blocking(move || check())
            .await
            .expect("wait_for_condition predicate task panicked");
        if satisfied {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {timeout:?} waiting for {description}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn write_file(dir: &Path, name: &str, contents: &str) {
    std::fs::write(dir.join(name), contents).unwrap_or_else(|err| panic!("write {name}: {err}"));
}

fn git_cmd(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git must execute");
    assert!(
        output.status.success(),
        "git {args:?} failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_init_and_commit(cwd: &Path) {
    git_cmd(cwd, &["init", "--initial-branch=main"]);
    git_commit(cwd, "seed chaos manifests");
}

fn git_commit(cwd: &Path, message: &str) {
    git_cmd(cwd, &["add", "--all"]);
    git_cmd(
        cwd,
        &[
            "-c",
            "user.name=FerrisCD Chaos Test",
            "-c",
            "user.email=chaos@ferriscd.test",
            // The fixture repo is throwaway; never depend on the host's signing setup.
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
    );
}

fn current_kube_context() -> String {
    kubectl_stdout(&["config", "current-context"])
}

fn kubectl(args: &[&str]) -> Output {
    Command::new("kubectl")
        .args(args)
        .output()
        .expect("kubectl must run")
}

fn kubectl_stdout(args: &[&str]) -> String {
    let output = kubectl(args);
    assert!(
        output.status.success(),
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn kubectl_stdin(args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new("kubectl")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kubectl must start");
    child
        .stdin
        .as_mut()
        .expect("piped stdin")
        .write_all(stdin.as_bytes())
        .expect("write kubectl stdin");
    child.wait_with_output().expect("kubectl finish")
}

fn install_crds() {
    let crds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crds");
    let output = kubectl(&["apply", "-f", &crds.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/crds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ensure_namespace(namespace: &str) {
    let manifest = format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n");
    let output = kubectl_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating namespace {namespace} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ensure_default_project() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/manifests/default-project.yaml");
    let output = kubectl(&["apply", "-f", &manifest.display().to_string()]);
    assert!(
        output.status.success(),
        "applying default-project.yaml failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn apply_live_application(
    app_name: &str,
    target_ns: &str,
    repo_url: &str,
    prune: bool,
    requeue_seconds: u32,
) {
    let manifest = format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {app_name}
  namespace: {CONTROL_NAMESPACE}
spec:
  project: default
  source:
    git:
      repoURL: {repo_url}
      targetRevision: main
      path: .
  destination:
    cluster: in-cluster
    namespace: {target_ns}
  syncPolicy:
    automated:
      prune: {prune}
      selfHeal: true
    syncOptions:
      createNamespace: true
  requeueAfterSeconds: {requeue_seconds}
"#
    );
    let output = kubectl_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying Application {app_name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn app_jsonpath(app_name: &str, template: &str) -> String {
    let output = kubectl(&[
        "get",
        "application",
        app_name,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={template}"),
    ]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn app_ready_status(app_name: &str) -> Option<String> {
    let s = app_jsonpath(
        app_name,
        "{.status.conditions[?(@.type==\"Ready\")].status}",
    );
    if s.is_empty() { None } else { Some(s) }
}

fn app_inventory_key_set(app_name: &str) -> BTreeSet<String> {
    app_jsonpath(app_name, "{.status.inventory[*].key}")
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn live_object_exists(kind: &str, name: &str, namespace: &str) -> bool {
    kubectl(&["get", kind, name, "-n", namespace, "-o", "name"])
        .status
        .success()
}

fn live_object_uid(kind: &str, name: &str, namespace: &str) -> Option<String> {
    let output = kubectl(&[
        "get",
        kind,
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.metadata.uid}",
    ]);
    if !output.status.success() {
        return None;
    }
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if uid.is_empty() { None } else { Some(uid) }
}

fn live_configmap_key(namespace: &str, name: &str) -> Option<String> {
    let output = kubectl(&[
        "get",
        "configmap",
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.data.key}",
    ]);
    if !output.status.success() {
        return None;
    }
    let val = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if val.is_empty() { None } else { Some(val) }
}
