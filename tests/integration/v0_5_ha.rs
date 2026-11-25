//! Live `v0.5` HA tests: remote-cluster delivery (`T13.1`) and `Lease` leader election (`T13.2`).
//!
//! # Safety gate
//!
//! Both tests **must never touch a non-`kind` cluster**. The first thing each one does is assert
//! that `kubectl config current-context` starts with `kind-`, mirroring the `test-integration`
//! Makefile guard. Both are `#[ignore]`d so `make gate` never needs a cluster; invoke them
//! explicitly:
//!
//! ```text
//! make kind-up
//! kind create cluster --name ferriscd-workload     # the remote cluster T13.1 delivers into
//! kubectl config use-context kind-ferriscd-dev
//! cargo test -p ferriscd-controller --test v0_5_ha -- --ignored --test-threads=1
//! ```
//!
//! # What these pin (and the hermetic tests cannot)
//!
//! 1. **Remote delivery.** A `ferriscd.io/secret-type=cluster` `Secret` registering
//!    `kind-ferriscd-workload` is observed by the **production** watch (`SecretClusterSource`), and
//!    produces a client that really talks to *that* API server: the `Application` is reconciled from
//!    the control plane, the `ConfigMap` lands on the workload cluster, nothing lands on the control
//!    plane, and a prune removes it from the workload cluster again. Deleting the `Secret` then
//!    revokes the registration (finding M6).
//! 2. **Single leader.** Two `LeaseElector`s over the same real `Lease` (one per simulated
//!    replica, in one process — see the note in the test) cannot both lead; the standby takes over
//!    once the leader stops renewing (the `SIGKILL` case), and a graceful release hands the lease
//!    over immediately.
//!
//! Hermetic coverage of the same rules (parsing, TLS policy, handle reuse, acquire/renew/lose/
//! release, token cancellation) lives in `crates/ferriscd-controller/src/{cluster_manager,
//! leader_election}.rs` and `crates/ferriscd-controller/src/sync.rs`.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ferriscd_controller::cluster_manager::{
    ClusterError, ClusterHandle, ClusterManager, ClusterName, ClusterOptions, KubeClusterBuilder,
    SECRET_TYPE_CLUSTER, SecretClusterSource,
};
use ferriscd_controller::credentials::SECRET_TYPE_LABEL;
use ferriscd_controller::discovery::DiscoveryCache;
use ferriscd_controller::dry_run::DynamicDryRunApi;
use ferriscd_controller::impersonation::{
    ImpersonatingAccess, ImpersonationPool, ensure_crypto_provider,
};
use ferriscd_controller::leader_election::{
    AcquireOutcome, HoldOutcome, KubeLeaseApi, LeaderElection, LeaderElectionConfig, LeaseApi,
    LeaseElector,
};
use ferriscd_controller::live_state::DynamicApiSource;
use ferriscd_controller::reconcile::{ApiStatusWriter, ReconcileContext};
use ferriscd_controller::sync::{DynamicApiApplier, InventorySyncPipeline};
use ferriscd_controller::{ApiProjectSource, ApplicationNamespaces, ApplicationScope};
use ferriscd_crd::Application;
use ferriscd_crd::status::{ApplicationStatus, CONDITION_READY, SyncStatus};
use ferriscd_engine::repo::{
    GixGitClient, GixGitClientConfig, RepoCache, RepoCacheConfig, RepoUrlPolicy,
};
use kube::Api;
use tokio_util::sync::CancellationToken;

/// Control-plane namespace.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Namespace the workload `Application` deploys into (on the remote cluster).
const DESTINATION_NAMESPACE: &str = "ha-workload";
/// `Application` name.
const APPLICATION_NAME: &str = "ha-app";
/// The remote cluster's registration name (and the `Secret`'s name).
const REMOTE_CLUSTER: &str = "kind-ferriscd-workload";
/// The remote cluster's kubeconfig context (the `kind` cluster itself is named `ferriscd-workload`).
const REMOTE_CONTEXT: &str = "kind-ferriscd-workload";
/// The ConfigMap every commit declares.
const CONFIGMAP_NAME: &str = "ha-settings";

// ---------------------------------------------------------------------------
// T13.1 — remote cluster delivery
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires TWO live kind clusters (make kind-up + kind create cluster --name ferriscd-workload)"]
async fn an_application_lands_on_a_secret_registered_remote_cluster_and_is_pruned_from_it() {
    // Safety rail (AGENTS.md): never run a live test against a non-`kind` context.
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    assert!(
        kind_context_exists(REMOTE_CONTEXT),
        "this test needs the workload cluster; create it with: kind create cluster --name ferriscd-workload"
    );

    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace_on(REMOTE_CONTEXT, DESTINATION_NAMESPACE);
    apply_manifest(&project_manifest());
    let _cleanup = ClusterCleanup::new();

    // The registry: a real in-cluster handle plus a registration built from the workload
    // cluster's own kubeconfig (server, CA and credentials), exactly as an operator would.
    let mut fixture = Fixture::new().await;
    // `T13.1` finding M6: the registry is driven by the **production** watch — not by a direct
    // `seed` — so this test exercises the namespaced `SecretClusterSource` and the invalidation it
    // owns, not a convenience path production never takes.
    fixture.start_registry();
    fixture.register_remote_cluster();
    fixture.wait_for_cluster(REMOTE_CLUSTER, true).await;
    assert_eq!(
        fixture.clusters.names(),
        vec![REMOTE_CLUSTER.to_owned()],
        "the Secret must have been observed by the registry's own watch"
    );

    // --- deploy -----------------------------------------------------------------
    fixture.commit(&[("configmap.yaml", configmap_manifest(DESTINATION_NAMESPACE))]);
    fixture.apply_application("prune: true");
    fixture
        .reconcile()
        .await
        .expect("a registered remote cluster must reconcile");

    let status = fixture.read_status().await;
    assert_eq!(
        sync_status(&status),
        Some(SyncStatus::Synced),
        "the remote reconcile must report Synced: {status:?}"
    );
    assert!(
        status.condition(CONDITION_READY).is_some(),
        "/status is patched on the control plane"
    );
    assert!(
        configmap_exists(REMOTE_CONTEXT, DESTINATION_NAMESPACE),
        "the ConfigMap must land on the remote cluster"
    );
    assert!(
        !configmap_exists(&context, DESTINATION_NAMESPACE),
        "nothing may land on the control plane for a remote destination"
    );
    assert!(
        has_finalizer(&fixture.read_application().await),
        "the finalizer stays on the control-plane object"
    );

    // --- prune ------------------------------------------------------------------
    fixture.commit(&[("unrelated.yaml", UNRELATED_CONFIGMAP.to_owned())]);
    fixture
        .reconcile()
        .await
        .expect("the prune pass must reconcile");
    assert!(
        !configmap_exists(REMOTE_CONTEXT, DESTINATION_NAMESPACE),
        "a prune must delete from the remote cluster, not the control plane"
    );

    // --- revocation -------------------------------------------------------------
    // Deleting the registration `Secret` must unregister the cluster: a revoked credential can
    // never stay addressable, and the next pass for that destination is a terminal
    // `NotFound` (finding `C5`'s escape hatch, wired to a real `Delete` event here).
    let _ = kubectl(&[
        "-n",
        CONTROL_NAMESPACE,
        "delete",
        "secret",
        REMOTE_CLUSTER,
        "--ignore-not-found=true",
    ]);
    fixture.wait_for_cluster(REMOTE_CLUSTER, false).await;
    assert!(
        matches!(
            fixture.clusters.get(REMOTE_CLUSTER),
            Err(ClusterError::NotFound { .. })
        ),
        "a deleted registration must stop resolving"
    );
}

// ---------------------------------------------------------------------------
// T13.2 — leader election
// ---------------------------------------------------------------------------

/// Two electors, one `Lease`, one leader.
///
/// # Deviation from the roadmap (recorded, finding M7)
///
/// `T13.2`'s verification says "kill the leader (`SIGKILL`)". This test instead keeps **both
/// replicas in one process** and aborts the leader's renewing task, because the properties the
/// failover depends on are all *client-side*: (a) the optimistic-concurrency write, (b) the
/// `renewTime` expiry, and (c) the release path. Each is exercised here against the **real** API
/// server with two independent `Api<Lease>` clients standing in for two replicas, so what is lost
/// is only the process boundary — not any behaviour the elector owns. Spawning two controller
/// binaries would add a `SIGKILL` and a cluster-wide restart to the test without touching (a)–(c).
///
/// The deviation is bounded by an explicit assertion: takeover must happen within
/// `lease_duration + 2s` of the last renewal, which is the roadmap's own acceptance criterion.
#[tokio::test]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn only_one_replica_leads_and_the_standby_takes_over() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    let _cleanup = LeaseCleanup;
    LeaseCleanup::delete();

    let client = live_client().await;
    // The minimum legal timings, so the failover is observable without a 15 s wait.
    let config = |identity: &str| {
        LeaderElectionConfig::new(CONTROL_NAMESPACE, identity)
            .with_lease_name("ferriscd-ha-test")
            .with_lease_duration(Duration::from_secs(3))
            .with_renew_interval(Duration::from_millis(500))
            .with_retry_interval(Duration::from_millis(200))
    };
    let api: Arc<dyn LeaseApi> = Arc::new(KubeLeaseApi::new(client.clone(), CONTROL_NAMESPACE));

    let first = LeaderElection::new(Arc::new(
        LeaseElector::new(api.clone(), config("replica-0")).expect("valid config"),
    ));
    let second = LeaderElection::new(Arc::new(
        LeaseElector::new(api.clone(), config("replica-1")).expect("valid config"),
    ));

    // --- only one leader --------------------------------------------------------
    let stop = CancellationToken::new();
    let leader = first
        .campaign(&stop)
        .await
        .expect("campaign")
        .expect("the first replica must win the empty lease");
    assert_eq!(
        second
            .elector()
            .try_acquire()
            .await
            .expect("acquire attempt"),
        AcquireOutcome::Held {
            holder: "replica-0".to_owned()
        },
        "the standby must not steal a live lease"
    );

    // Keep the lease alive while the standby keeps losing.
    let leader_token = leader.token();
    let hold = tokio::spawn({
        let stop = stop.clone();
        async move {
            // `hold` returns when the lease is lost or `stop` fires; three renewals is enough here.
            tokio::time::timeout(Duration::from_millis(1500), leader.hold(&stop))
                .await
                .ok()
        }
    });
    for _ in 0..5 {
        assert_eq!(
            second
                .elector()
                .try_acquire()
                .await
                .expect("acquire attempt"),
            AcquireOutcome::Held {
                holder: "replica-0".to_owned()
            }
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // A running leader never turns its own token off.
    assert!(!leader_token.is_cancelled());

    // --- kill the leader (stop renewing, do not release) ------------------------
    // The `hold` task is dropped without releasing: exactly what a `SIGKILL` looks like to the
    // API server. The standby then waits out the lease.
    hold.abort();
    let _ = hold.await;
    // Measured against the roadmap's criterion: `lease_duration + 2s` (finding M7).
    let killed_at = tokio::time::Instant::now();
    let takeover = tokio::time::timeout(Duration::from_secs(12), second.campaign(&stop))
        .await
        .expect("the standby must acquire the expired lease")
        .expect("campaign")
        .expect("the standby must become the leader");
    let takeover_latency = killed_at.elapsed();
    assert!(
        takeover_latency <= Duration::from_secs(3) + Duration::from_secs(2),
        "takeover took {takeover_latency:?}: the roadmap requires lease_duration + 2s"
    );
    assert_eq!(
        second.elector().try_acquire().await.expect("acquire"),
        AcquireOutcome::Acquired,
        "the new leader holds the lease"
    );

    // --- graceful release hands the lease over at once --------------------------
    stop.cancel();
    let outcome = takeover.hold(&stop).await.expect("hold");
    assert_eq!(outcome, HoldOutcome::Released);
    assert!(
        takeover.token().is_cancelled(),
        "a released leader stops reconciling"
    );
    let reacquired = tokio::time::timeout(Duration::from_secs(5), first.elector().try_acquire())
        .await
        .expect("a released lease is free")
        .expect("acquire");
    assert_eq!(reacquired, AcquireOutcome::Acquired);
    first.elector().release().await.expect("release");
}

// ---------------------------------------------------------------------------
// Controller wiring
// ---------------------------------------------------------------------------

/// The production wiring of `ferriscd controller`, for one test process.
struct Fixture {
    client: kube::Client,
    ctx: Arc<ReconcileContext>,
    clusters: Arc<ClusterManager>,
    repo: PathBuf,
    /// The registry's own watch, once [`Fixture::start_registry`] ran.
    registry: Option<RegistryWatch>,
    _temp: tempfile::TempDir,
}

/// The `SecretClusterSource` watch task, stopped when the fixture drops.
struct RegistryWatch {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RegistryWatch {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        ensure_crypto_provider();
        let kube_config = kube::Config::infer()
            .await
            .expect("kubeconfig must point at the kind cluster");
        let client = kube::Client::try_from(kube_config.clone()).expect("kube client");

        let temp = tempfile::tempdir().expect("create the fixture directory");
        let repo = temp.path().join("repo");
        std::fs::create_dir_all(&repo).expect("create the fixture repository");
        git(&repo, &["init", "--initial-branch=main"]);

        let work_root = temp.path().join("work");
        let repos = Arc::new(RepoCache::new(
            Arc::new(GixGitClient::new(
                GixGitClientConfig::new()
                    .with_url_policy(RepoUrlPolicy::AllowLocal)
                    .with_work_root(&work_root),
            )),
            RepoCacheConfig::new(&work_root),
        ));
        let pool = Arc::new(ImpersonationPool::new(&kube_config).expect("impersonation pool"));
        let clusters = Arc::new(ClusterManager::new(
            Arc::new(ClusterHandle::new(
                ClusterName::in_cluster(),
                client.clone(),
                DiscoveryCache::new(client.clone()),
                pool.clone(),
            )),
            CONTROL_NAMESPACE,
            ClusterOptions::strict(),
            Arc::new(KubeClusterBuilder::new(ClusterOptions::strict())),
        ));
        let scope = ApplicationScope::new(
            CONTROL_NAMESPACE,
            ApplicationNamespaces::Listed(vec![CONTROL_NAMESPACE.to_owned()]),
        );
        let pipeline = Arc::new(
            InventorySyncPipeline::new(
                repos,
                DiscoveryCache::new(client.clone()),
                Arc::new(DynamicApiSource::new(client.clone())),
                Arc::new(DynamicApiApplier::new(client.clone())),
                Arc::new(DynamicDryRunApi::new(client.clone())),
            )
            .with_url_policy(RepoUrlPolicy::AllowLocal)
            .with_project_source(Arc::new(ApiProjectSource::new(
                client.clone(),
                CONTROL_NAMESPACE,
            )))
            .with_application_scope(scope)
            .with_impersonation_source(Arc::new(ImpersonatingAccess::new(pool)))
            .with_cluster_source(clusters.clone()),
        );
        let apps_api = Api::<Application>::namespaced(client.clone(), CONTROL_NAMESPACE);
        let status = Arc::new(ApiStatusWriter::new(apps_api.clone()).with_client(client.clone()));
        let ctx =
            Arc::new(ReconcileContext::new(apps_api, pipeline, status).with_client(client.clone()));

        Self {
            client,
            ctx,
            clusters,
            repo,
            registry: None,
            _temp: temp,
        }
    }

    /// Starts the registry's own watch, exactly as `ferriscd controller` does at startup.
    fn start_registry(&mut self) {
        let stop = CancellationToken::new();
        let task = tokio::spawn(self.clusters.clone().run(
            Arc::new(SecretClusterSource::new(
                self.client.clone(),
                CONTROL_NAMESPACE,
            )),
            stop.clone(),
        ));
        self.registry = Some(RegistryWatch { stop, task });
    }

    /// Creates the remote-cluster `Secret` from the workload cluster's own kubeconfig; the
    /// registry's watch (not a direct `seed`) is what turns it into a handle.
    fn register_remote_cluster(&self) {
        let manifest = cluster_secret_manifest(REMOTE_CLUSTER, REMOTE_CONTEXT);
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "secret",
            REMOTE_CLUSTER,
            "--ignore-not-found=true",
        ]);
        apply_manifest(&manifest);
    }

    /// Polls the registry until it reports (or no longer reports) `name`.
    ///
    /// A watch is asynchronous by nature, so the live test waits for the observation it is about
    /// instead of sleeping a fixed amount.
    async fn wait_for_cluster(&self, name: &str, present: bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            let registered = self.clusters.names().iter().any(|known| known == name);
            if registered == present {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the cluster registry did not {} {name} within 60s (it holds {:?})",
                if present { "register" } else { "forget" },
                self.clusters.names(),
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn commit(&self, files: &[(&str, String)]) {
        for entry in std::fs::read_dir(&self.repo)
            .expect("read the fixture directory")
            .flatten()
        {
            if entry.file_name() != ".git" {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        for (name, contents) in files {
            std::fs::write(self.repo.join(name), contents).expect("write the fixture manifest");
        }
        git(&self.repo, &["add", "--all"]);
        git(
            &self.repo,
            &[
                "-c",
                "user.name=FerrisCD Test",
                "-c",
                "user.email=ferriscd@example.com",
                "commit",
                "--allow-empty",
                "-m",
                "fixture",
            ],
        );
    }

    fn apply_application(&self, automation: &str) {
        let manifest = application_manifest(&self.repo.display().to_string(), automation);
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "application",
            APPLICATION_NAME,
            "--ignore-not-found=true",
            "--timeout=120s",
        ]);
        apply_manifest(&manifest);
    }

    async fn reconcile(&self) -> Result<(), ferriscd_controller::reconcile::ControllerError> {
        let app = self.read_application().await;
        ferriscd_controller::reconcile::reconcile_instance(Arc::new(app), self.ctx.clone())
            .await
            .map(|_action| ())
    }

    async fn read_application(&self) -> Application {
        Api::<Application>::namespaced(self.client.clone(), CONTROL_NAMESPACE)
            .get(APPLICATION_NAME)
            .await
            .expect("the Application must exist")
    }

    async fn read_status(&self) -> ApplicationStatus {
        self.read_application().await.status.unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Manifests
// ---------------------------------------------------------------------------

const UNRELATED_CONFIGMAP: &str =
    "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: unrelated\ndata:\n  key: value\n";

fn configmap_manifest(namespace: &str) -> String {
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {CONFIGMAP_NAME}\n  namespace: {namespace}\ndata:\n  key: value\n"
    )
}

/// A project that authorizes the remote cluster and the destination namespace.
fn project_manifest() -> String {
    format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: ha
  namespace: {CONTROL_NAMESPACE}
spec:
  description: v0.5 HA fixture
  sourceRepos:
    - "*"
  sourceNamespaces:
    - {CONTROL_NAMESPACE}
  destinations:
    - cluster: {REMOTE_CLUSTER}
      namespace: {DESTINATION_NAMESPACE}
  clusterResourceWhitelist:
    - group: ""
      kind: Namespace
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
"#
    )
}

fn application_manifest(repo_url: &str, automation: &str) -> String {
    format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {APPLICATION_NAME}
  namespace: {CONTROL_NAMESPACE}
spec:
  project: ha
  source:
    git:
      repoURL: {repo_url}
      targetRevision: main
      path: .
  destination:
    cluster: {REMOTE_CLUSTER}
    namespace: {DESTINATION_NAMESPACE}
  syncPolicy:
    automated:
      {automation}
      selfHeal: true
  requeueAfterSeconds: 15
"#
    )
}

/// Builds a `ferriscd.io/secret-type=cluster` `Secret` from a kubeconfig context.
///
/// Reads the context's own server, CA bundle and credentials (bearer token or client certificate)
/// through `kubectl config view --raw`, which is what an operator copies into the Secret anyway.
fn cluster_secret_manifest(name: &str, context: &str) -> String {
    let view = kubectl_stdout(&[
        "config",
        "view",
        "--raw",
        "--minify",
        "-o",
        "json",
        "--context",
        context,
    ]);
    let view: serde_json::Value = serde_json::from_str(&view).expect("a kubeconfig JSON view");
    let cluster = view["clusters"]
        .as_array()
        .and_then(|clusters| clusters.first())
        .and_then(|entry| entry.get("cluster"))
        .expect("the context must name a cluster");
    let server = cluster["server"]
        .as_str()
        .expect("the cluster must have a server")
        .to_owned();
    let ca = cluster["certificate-authority-data"]
        .as_str()
        .map(str::to_owned);
    let user = view["users"]
        .as_array()
        .and_then(|users| users.first())
        .and_then(|entry| entry.get("user"))
        .cloned()
        .unwrap_or_default();

    let mut data = String::new();
    if let Some(ca) = ca {
        // `Secret.data` values are base64, and kubeconfig `-data` fields already are.
        data.push_str(&format!("  ca.crt: {ca}\n"));
    }
    let mut string_data = format!("  server: {server}\n");
    if let Some(token) = user["token"].as_str().filter(|token| !token.is_empty()) {
        string_data.push_str(&format!("  bearerToken: {token}\n"));
    } else {
        for (key, field) in [
            ("tls.crt", "client-certificate-data"),
            ("tls.key", "client-key-data"),
        ] {
            let value = user[field]
                .as_str()
                .unwrap_or_else(|| panic!("the kubeconfig user needs a token or {field}"));
            data.push_str(&format!("  {key}: {value}\n"));
        }
    }

    format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: {CONTROL_NAMESPACE}
  labels:
    {SECRET_TYPE_LABEL}: {SECRET_TYPE_CLUSTER}
data:
{data}stringData:
{string_data}"#
    )
}

// ---------------------------------------------------------------------------
// Cluster helpers
// ---------------------------------------------------------------------------

/// Deletes everything this test creates, even when an assertion panics.
struct ClusterCleanup;

impl ClusterCleanup {
    fn new() -> Self {
        Self::delete_all();
        Self
    }

    fn delete_all() {
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "application",
            APPLICATION_NAME,
            "--ignore-not-found=true",
            "--timeout=120s",
        ]);
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "secret",
            REMOTE_CLUSTER,
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "appproject",
            "ha",
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "--context",
            REMOTE_CONTEXT,
            "-n",
            DESTINATION_NAMESPACE,
            "delete",
            "configmap",
            CONFIGMAP_NAME,
            "--ignore-not-found=true",
        ]);
    }
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        Self::delete_all();
    }
}

/// Removes the leader-election `Lease` between runs.
struct LeaseCleanup;

impl LeaseCleanup {
    fn delete() {
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "lease",
            "ferriscd-ha-test",
            "--ignore-not-found=true",
        ]);
    }
}

impl Drop for LeaseCleanup {
    fn drop(&mut self) {
        Self::delete();
    }
}

async fn live_client() -> kube::Client {
    ensure_crypto_provider();
    let config = kube::Config::infer()
        .await
        .expect("kubeconfig must point at the kind cluster");
    kube::Client::try_from(config).expect("kube client")
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
    apply_manifest(&manifest);
}

fn ensure_namespace_on(context: &str, namespace: &str) {
    let manifest = format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n");
    let output = kubectl_with_stdin(&["--context", context, "apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating namespace {namespace} on {context} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn apply_manifest(manifest: &str) {
    let output = kubectl_with_stdin(&["apply", "-f", "-"], manifest);
    assert!(
        output.status.success(),
        "applying a fixture manifest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn configmap_exists(context: &str, namespace: &str) -> bool {
    kubectl(&[
        "--context",
        context,
        "get",
        "configmap",
        CONFIGMAP_NAME,
        "-n",
        namespace,
        "-o",
        "name",
    ])
    .status
    .success()
}

/// Whether `context` exists in the local kubeconfig.
fn kind_context_exists(context: &str) -> bool {
    kubectl_stdout(&["config", "get-contexts", "-o", "name"])
        .lines()
        .any(|existing| existing.trim() == context)
}

fn has_finalizer(app: &Application) -> bool {
    app.metadata.finalizers.as_ref().is_some_and(|finalizers| {
        finalizers
            .iter()
            .any(|item| item == ferriscd_controller::reconcile::FINALIZER)
    })
}

fn sync_status(status: &ApplicationStatus) -> Option<SyncStatus> {
    status.sync.as_ref().map(|sync| sync.status)
}

fn current_kube_context() -> String {
    kubectl_stdout(&["config", "current-context"])
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

fn kubectl(args: &[&str]) -> Output {
    Command::new("kubectl")
        .args(args)
        .output()
        .expect("kubectl must run")
}

fn kubectl_with_stdin(args: &[&str], stdin: &str) -> Output {
    use std::io::Write as _;

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
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("write the manifest to kubectl stdin");
    child.wait_with_output().expect("kubectl must finish")
}

fn git(cwd: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git {args:?} failed (cwd={}): stdout={}, stderr={}",
        cwd.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
