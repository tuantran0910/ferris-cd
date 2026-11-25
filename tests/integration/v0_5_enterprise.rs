//! Live `v0.5` enterprise acceptance suite (`T13.4`).
//!
//! This is the **cross-cutting** end-to-end pass for the `v0.5` milestone: one file that proves the
//! four boundaries Phase 12/13 built, in the order an operator would meet them.
//!
//! 1. **`AppProject` authorization** — an `Application` whose destination namespace or rendered
//!    Kubernetes kind is not in the project is refused with `Ready=False, reason=PolicyViolation`,
//!    and nothing is deployed. The project is the boundary; RBAC is only the second line.
//! 2. **ServiceAccount impersonation** — a tenant `Application` deploys **as its own
//!    `ServiceAccount`**, through a **group** `RoleBinding`
//!    (`system:serviceaccounts:<namespace>`), which can only work if the controller sends
//!    `Impersonate-Group` as well as `Impersonate-User` (finding H5); what the tenant may not do is
//!    refused by the **API server** with `403`, naming the impersonated identity.
//! 3. **Remote cluster delivery** — a `ferriscd.io/secret-type=cluster` `Secret` turns a second
//!    `kind` cluster into a destination: the `Application` deploys there and prunes there, while
//!    `Application.status` and the finalizer stay on the control plane.
//! 4. **`Lease` failover** — two replicas over one `Lease`: exactly one leads, the standby takes
//!    over within `lease_duration + 2s` of the leader's last renewal, and a graceful release hands
//!    the lease over at once. The lease is the **per-shard** name (`T13.3`), proving that a sharded
//!    fleet elects one leader *per shard* rather than one for everything.
//!
//! # Safety gate
//!
//! Every test **must never touch a non-`kind` cluster**. The first thing each one does is assert
//! that `kubectl config current-context` starts with `kind-`, mirroring the `test-integration`
//! Makefile guard. All four are `#[ignore]`d, so `make gate` never needs a cluster.
//!
//! ```text
//! make kind-up
//! kind create cluster --name ferriscd-workload          # the remote cluster for case 3
//! kubectl config use-context kind-ferriscd-dev
//! cargo test -p ferriscd-controller --test v0_5_enterprise -- --ignored --test-threads=1
//! ```
//!
//! # Scope, and what is deliberately *not* duplicated here
//!
//! The deeper variants of each boundary live in their own files, and this suite does not replace
//! them:
//!
//! * `tests/integration/v0_5_multi_tenancy.rs` covers the missing-`serviceAccountName` refusal, the
//!   tenant finalizer landing in the tenant namespace, and two independent `403` shapes;
//! * `tests/integration/v0_5_ha.rs` covers the registry's **own watch** (`SecretClusterSource`)
//!   driving cluster registration and revocation, and a longer failover sequence;
//! * `tests/integration/v0_5_repo_credentials.rs` covers scoped repository credentials.
//!
//! What is unique here: the project's *destination* and *kind* allow-lists (case 1), impersonation
//! proven through a group `RoleBinding` **and** a project that permits the forbidden target so only
//! the API server can refuse it (case 2), remote delivery driven by a `Secret` read back from the
//! API server (case 3), and failover over a **per-shard** lease (case 4).
//!
//! # Remote-cluster impersonation RBAC (trap guard)
//!
//! Case 3 deploys to the remote cluster **without** `spec.serviceAccountName`, i.e. as the
//! credential in the cluster `Secret`. That is the control-plane-owner case: the remote credential
//! is whatever an operator put in the `Secret`, so it needs the workload verbs the project's
//! `destinations` allow. A *tenant* `Application` on a remote cluster is a different grant, and the
//! fixture in `v0_5_multi_tenancy.rs` documents its shape:
//!
//! * the `Secret`'s credential needs `users`, `groups`, `serviceaccounts` **`impersonate`** on the
//!   *remote* API server (the controller impersonates there with the remote connector), and
//! * the remote `ServiceAccount` (`<remote-namespace>/<spec.serviceAccountName>`) needs its own
//!   RBAC on the remote cluster, because impersonation only *narrows* the request — it never grants
//!   anything.
//!
//! FerrisCD never writes a `ferriscd.io` CR on the remote cluster (`status` and the finalizer stay
//! on the control plane), so the remote credential needs no FerrisCD permissions at all.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ferriscd_controller::cluster_manager::{
    ClusterHandle, ClusterManager, ClusterName, ClusterOptions, KubeClusterBuilder,
    SECRET_TYPE_CLUSTER,
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
use ferriscd_controller::{ApiProjectSource, ApplicationNamespaces, ApplicationScope, Sharding};
use ferriscd_crd::Application;
use ferriscd_crd::status::{ApplicationStatus, CONDITION_READY, ConditionStatus, SyncStatus};
use ferriscd_engine::repo::{
    GixGitClient, GixGitClientConfig, RepoCache, RepoCacheConfig, RepoUrlPolicy,
};
use kube::Api;
use tokio_util::sync::CancellationToken;

/// Control-plane namespace (holds the `AppProject`, the cluster `Secret` and the `Lease`).
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Namespace the tenant `Application` lives in (a tenant, not the control plane).
const TENANT_NAMESPACE: &str = "enterprise-team";
/// Namespace a tenant `Application` deploys into, and where its `ServiceAccount` lives.
const DESTINATION_NAMESPACE: &str = "enterprise-app";
/// Namespace the project does **not** list in `spec.destinations` (case 1).
const DENIED_NAMESPACE: &str = "enterprise-elsewhere";
/// Namespace the project **does** permit, but the tenant's RBAC does not (case 2) — so only the API
/// server can refuse the write.
const FORBIDDEN_NAMESPACE: &str = "kube-system";
/// Namespace on the **remote** cluster (case 3).
const REMOTE_NAMESPACE: &str = "enterprise-remote";
/// The project every `Application` in this suite references.
const PROJECT: &str = "enterprise";
/// The `ServiceAccount` the tenant deploys as.
const SERVICE_ACCOUNT: &str = "deployer";
/// The group the `RoleBinding` grants through: only `Impersonate-Group` can satisfy it (finding H5).
const TENANT_GROUP: &str = "system:serviceaccounts:enterprise-app";
/// The identity the API server must name in its `403`s.
const IMPERSONATED_USER: &str = "system:serviceaccount:enterprise-app:deployer";
/// The `Application` name (one live object at a time).
const APPLICATION_NAME: &str = "enterprise-app";
/// The remote cluster's registration name (`spec.destination.cluster`).
const REMOTE_CLUSTER: &str = "kind-ferriscd-workload";
/// The remote cluster's kubeconfig context (`kind` names it `ferriscd-workload`).
const REMOTE_CONTEXT: &str = "kind-ferriscd-workload";
/// The `Lease` the failover test uses. Deliberately the **per-shard** name (`T13.3`).
const LEASE_SHARD_ID: u32 = 0;
/// Total shards the failover test's lease belongs to.
const LEASE_TOTAL_SHARDS: u32 = 2;
/// The ConfigMap every commit declares.
const CONFIGMAP_NAME: &str = "enterprise-settings";

// ---------------------------------------------------------------------------
// Case 1 — `AppProject` namespace/kind rejection (`T12.1`)
// ---------------------------------------------------------------------------

/// **`T12.1`/`T13.4`:** the project is the boundary. A destination namespace or a Kubernetes kind it
/// does not list is refused **before** anything is applied, and the refusal is a
/// `PolicyViolation` — not a generic sync error an operator could mistake for a transient failure.
#[tokio::test]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn an_application_outside_the_projects_namespaces_and_kinds_is_denied() {
    require_kind_context();
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace(TENANT_NAMESPACE);
    ensure_namespace(DESTINATION_NAMESPACE);
    ensure_namespace(DENIED_NAMESPACE);
    apply_manifest(&project_manifest());
    apply_manifest(&tenant_rbac_manifest());
    let _cleanup = ClusterCleanup::new();

    let fixture = Fixture::new().await;

    // (a) A destination namespace the project does not list.
    fixture.commit(&[("configmap.yaml", configmap_manifest(DENIED_NAMESPACE))]);
    fixture.apply_application(DENIED_NAMESPACE);
    let err = fixture
        .reconcile()
        .await
        .expect_err("a destination outside spec.destinations must be denied");
    let message = err.to_string();
    assert!(
        message.contains("spec.destinations"),
        "the denial must name the allow-list: {message}"
    );
    assert!(
        message.contains(DENIED_NAMESPACE),
        "the denial must name the rejected namespace: {message}"
    );
    assert!(
        !configmap_exists(DENIED_NAMESPACE, CONFIGMAP_NAME),
        "a denied Application must deploy nothing"
    );
    let status = fixture.read_status().await;
    let ready = status
        .condition(CONDITION_READY)
        .expect("the denial must still patch /status (always-update-status)");
    assert_eq!(
        ready.reason, "PolicyViolation",
        "a project denial is a PolicyViolation: {ready:?}"
    );
    assert_eq!(ready.status, ConditionStatus::False);

    // (b) A namespaced kind the project's whitelist does not include.
    fixture.commit(&[(
        "deployment.yaml",
        deployment_manifest(DESTINATION_NAMESPACE),
    )]);
    fixture.apply_application(DESTINATION_NAMESPACE);
    let err = fixture
        .reconcile()
        .await
        .expect_err("a kind outside namespaceResourceWhitelist must be denied");
    let message = err.to_string();
    assert!(
        message.contains("namespaceResourceWhitelist"),
        "the denial must name the allow-list: {message}"
    );
    assert!(
        !kubectl(&[
            "get",
            "deployment",
            APPLICATION_NAME,
            "-n",
            DESTINATION_NAMESPACE,
            "-o",
            "name"
        ])
        .status
        .success(),
        "a denied Deployment must not exist"
    );

    // (c) Non-vacuous: the very same project *does* authorize a whitelisted kind into a listed
    // namespace. Without this, (a) and (b) could pass simply because the project denies everything.
    fixture.commit(&[("configmap.yaml", configmap_manifest(DESTINATION_NAMESPACE))]);
    fixture.apply_application(DESTINATION_NAMESPACE);
    fixture
        .reconcile()
        .await
        .expect("the project authorizes this ConfigMap and destination");
    assert!(
        configmap_exists(DESTINATION_NAMESPACE, CONFIGMAP_NAME),
        "the authorized ConfigMap must be applied"
    );
    assert_eq!(
        sync_status(&fixture.read_status().await),
        Some(SyncStatus::Synced),
        "an authorized tenant Application syncs"
    );
}

// ---------------------------------------------------------------------------
// Case 2 — ServiceAccount impersonation (`T12.2` + `T12.3`)
// ---------------------------------------------------------------------------

/// **`T12.3`/`T13.4`:** the tenant deploys as its own `ServiceAccount`, authorized through a
/// **group** `RoleBinding`, and is bounded by that `ServiceAccount`'s RBAC — never by the
/// controller's.
///
/// Both halves matter:
///
/// * the success case cannot pass on the controller's identity: only `system:serviceaccounts:<ns>`
///   is bound, and the controller's own `ServiceAccount` is not in that group;
/// * the failure case cannot come from the policy: the project permits `kube-system` on purpose, so
///   the `403` naming `system:serviceaccount:…:deployer` can only be the API server refusing the
///   impersonated identity.
#[tokio::test]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn a_tenant_deploy_is_impersonated_and_bounded_by_the_api_server() {
    require_kind_context();
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace(TENANT_NAMESPACE);
    ensure_namespace(DESTINATION_NAMESPACE);
    apply_manifest(&project_manifest());
    apply_manifest(&tenant_rbac_manifest());
    let _cleanup = ClusterCleanup::new();

    let fixture = Fixture::new().await;

    // (a) Authorized: the ConfigMap lands in the tenant's own namespace, as the ServiceAccount.
    fixture.commit(&[("configmap.yaml", configmap_manifest(DESTINATION_NAMESPACE))]);
    fixture.apply_application(DESTINATION_NAMESPACE);
    fixture
        .reconcile()
        .await
        .expect("an authorized tenant Application must reconcile");
    assert!(
        configmap_exists(DESTINATION_NAMESPACE, CONFIGMAP_NAME),
        "only the group RoleBinding can authorize this write, so it required Impersonate-Group"
    );
    let status = fixture.read_status().await;
    assert_eq!(sync_status(&status), Some(SyncStatus::Synced), "{status:?}");
    assert!(
        has_finalizer(&fixture.read_application().await),
        "the finalizer stays on the Application, in {TENANT_NAMESPACE}"
    );

    // (b) Refused by the API server, not by the project.
    fixture.commit(&[("configmap.yaml", configmap_manifest(FORBIDDEN_NAMESPACE))]);
    fixture.apply_application(FORBIDDEN_NAMESPACE);
    let err = fixture
        .reconcile()
        .await
        .expect_err("the impersonated ServiceAccount has no RBAC in kube-system");
    let message = err.to_string();
    assert!(
        message.contains("forbidden") || message.contains("403"),
        "expected an API-server denial, got: {message}"
    );
    assert!(
        message.contains(IMPERSONATED_USER),
        "the denial must name the impersonated ServiceAccount ({IMPERSONATED_USER}): {message}"
    );
    assert!(
        !configmap_exists(FORBIDDEN_NAMESPACE, CONFIGMAP_NAME),
        "nothing may be created in {FORBIDDEN_NAMESPACE}"
    );
}

// ---------------------------------------------------------------------------
// Case 3 — remote `kind` cluster deploy and prune (`T13.1`)
// ---------------------------------------------------------------------------

/// **`T13.1`/`T13.4`:** a `Secret`-registered remote cluster is a real destination.
///
/// The `Application` lives in the control-plane namespace (a control-plane-owned Application, so no
/// remote impersonation is involved — see the trap-guard note in the module docs). The registry is
/// seeded from the `Secret` **read back from the API server**, so the production parser handles the
/// same bytes an operator applies.
#[tokio::test]
#[ignore = "requires TWO live kind clusters (make kind-up + kind create cluster --name ferriscd-workload)"]
async fn an_application_deploys_to_and_is_pruned_from_a_remote_kind_cluster() {
    require_kind_context();
    assert!(
        kind_context_exists(REMOTE_CONTEXT),
        "this test needs the workload cluster; create it with: kind create cluster --name ferriscd-workload"
    );
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace_on(REMOTE_CONTEXT, REMOTE_NAMESPACE);
    apply_manifest(&project_manifest());
    let _cleanup = ClusterCleanup::new();

    let fixture = Fixture::new().await;
    fixture.register_remote_cluster().await;

    // --- deploy -----------------------------------------------------------------
    fixture.commit(&[("configmap.yaml", configmap_manifest(REMOTE_NAMESPACE))]);
    fixture.apply_application_on(REMOTE_CLUSTER, REMOTE_NAMESPACE, CONTROL_NAMESPACE);
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
        "/status is patched on the control plane, never on the remote cluster"
    );
    assert!(
        configmap_exists_on(REMOTE_CONTEXT, REMOTE_NAMESPACE),
        "the ConfigMap must land on the remote cluster"
    );
    assert!(
        !configmap_exists(REMOTE_NAMESPACE, CONFIGMAP_NAME),
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
        !configmap_exists_on(REMOTE_CONTEXT, REMOTE_NAMESPACE),
        "a prune must delete from the remote cluster, not from the control plane"
    );
}

// ---------------------------------------------------------------------------
// Case 4 — 2-replica `Lease` failover (`T13.2`, per-shard leases from `T13.3`)
// ---------------------------------------------------------------------------

/// **`T13.2`/`T13.4`:** two replicas, one `Lease`, one leader — and a takeover within
/// `lease_duration + 2s`.
///
/// # Deviation from the roadmap, and why it is bounded
///
/// `T13.2` says "kill the leader (`SIGKILL`)". Both replicas live in this one process and the
/// leader's renewing task is aborted instead, because every property the failover depends on is
/// client-side: (a) the optimistic-concurrency write, (b) `renewTime` expiry and (c) the release
/// path. Each runs here against the **real** API server with two independent `Api<Lease>` clients,
/// so only the process boundary is missing. The deviation is bounded by an explicit assertion: the
/// takeover must happen within `lease_duration + 2s` of the last renewal, which is the roadmap's own
/// acceptance criterion.
///
/// The `Lease` is the **per-shard** name `ferriscd-leader-shard-0` (`T13.3`): a sharded fleet elects
/// one leader *per shard*, and this test pins that the name the elector writes is the shard's own —
/// not the single-leader `ferriscd-controller-leader`, which would make only one shard ever run.
#[tokio::test]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn two_replicas_elect_one_leader_and_fail_over_within_lease_plus_two_seconds() {
    require_kind_context();
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);

    let shard = Sharding::new(LEASE_SHARD_ID, LEASE_TOTAL_SHARDS).expect("valid shard");
    let lease_name = shard.lease_name();
    assert_ne!(
        lease_name,
        ferriscd_controller::DEFAULT_LEASE_NAME,
        "a sharded replica must never compete for the single-leader lease"
    );
    let _cleanup = LeaseCleanup::new(&lease_name);

    let client = live_client().await;
    let lease_duration = Duration::from_secs(3);
    let config = |identity: &str| {
        LeaderElectionConfig::new(CONTROL_NAMESPACE, identity)
            .with_lease_name(shard.lease_name())
            .with_lease_duration(lease_duration)
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

    // --- exactly one leader -----------------------------------------------------
    let stop = CancellationToken::new();
    let leader = first
        .campaign(&stop)
        .await
        .expect("campaign")
        .expect("the first replica must win the empty lease");
    assert_eq!(
        leader.elector().config().lease_name(),
        lease_name,
        "the elector writes the per-shard lease"
    );
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

    // Keep the lease alive while the standby keeps losing, so the takeover below is measured from a
    // lease that really was being renewed (not from one that had already expired).
    let leader_token = leader.token();
    let hold = tokio::spawn({
        let stop = stop.clone();
        async move {
            tokio::time::timeout(Duration::from_millis(2000), leader.hold(&stop))
                .await
                .ok()
        }
    });
    for _ in 0..4 {
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
    assert!(
        !leader_token.is_cancelled(),
        "a leader that keeps renewing never loses its own token"
    );

    // --- kill the leader (stop renewing, do not release) -------------------------
    // Dropping the `hold` task without a release is exactly what a `SIGKILL` looks like to the API
    // server: the lease stops being renewed and has to expire.
    hold.abort();
    let _ = hold.await;
    let killed_at = tokio::time::Instant::now();
    let takeover = tokio::time::timeout(Duration::from_secs(15), second.campaign(&stop))
        .await
        .expect("the standby must acquire the expired lease")
        .expect("campaign")
        .expect("the standby must become the leader");
    let takeover_latency = killed_at.elapsed();
    assert!(
        takeover_latency <= lease_duration + Duration::from_secs(2),
        "takeover took {takeover_latency:?}: the roadmap requires lease_duration + 2s \
         ({lease_duration:?} + 2s)"
    );
    assert_eq!(
        takeover.elector().config().lease_name(),
        lease_name,
        "the standby took the shard's lease, not another one"
    );

    // --- graceful release hands the lease over at once ---------------------------
    stop.cancel();
    let outcome = takeover.hold(&stop).await.expect("hold");
    assert_eq!(outcome, HoldOutcome::Released);
    assert!(
        takeover.token().is_cancelled(),
        "a released leader stops reconciling immediately"
    );
    let reacquired = tokio::time::timeout(Duration::from_secs(5), first.elector().try_acquire())
        .await
        .expect("a released lease is free")
        .expect("acquire");
    assert_eq!(
        reacquired,
        AcquireOutcome::Acquired,
        "the released lease is taken over without waiting for it to expire"
    );
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
    _temp: tempfile::TempDir,
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
        // `T12.3`: one shared connector for every impersonated identity, as the binary builds it.
        let pool = Arc::new(ImpersonationPool::new(&kube_config).expect("impersonation pool"));
        assert_eq!(pool.connectors(), 1, "the pool owns exactly one connector");
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
        // Two tenant namespaces are watched, so a tenant `Application` is reconciled, not dropped.
        let scope = ApplicationScope::new(
            CONTROL_NAMESPACE,
            ApplicationNamespaces::Listed(vec![TENANT_NAMESPACE.to_owned()]),
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
            .with_impersonation_source(Arc::new(ImpersonatingAccess::new(pool.clone())))
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
            _temp: temp,
        }
    }

    /// Creates the remote-cluster `Secret` from the workload cluster's own kubeconfig and seeds the
    /// registry with the `Secret` as the API server stored it.
    ///
    /// The registry's own watch (`SecretClusterSource`) is covered by
    /// `tests/integration/v0_5_ha.rs`; here the point is the *parser* and the *client* that the
    /// registry builds from a real registration, so the `Secret` is read back through the API
    /// (never hand-constructed) and then seeded.
    async fn register_remote_cluster(&self) {
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "secret",
            REMOTE_CLUSTER,
            "--ignore-not-found=true",
        ]);
        apply_manifest(&cluster_secret_manifest(REMOTE_CLUSTER, REMOTE_CONTEXT));
        let secret = Api::<k8s_openapi::api::core::v1::Secret>::namespaced(
            self.client.clone(),
            CONTROL_NAMESPACE,
        )
        .get(REMOTE_CLUSTER)
        .await
        .expect("the registration Secret must exist");
        self.clusters
            .seed(&secret)
            .await
            .expect("a valid registration Secret must be usable");
        assert!(
            self.clusters
                .names()
                .iter()
                .any(|name| name == REMOTE_CLUSTER),
            "the registry must resolve {REMOTE_CLUSTER}"
        );
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

    /// Applies a tenant `Application` (in [`TENANT_NAMESPACE`]) targeting `in-cluster`.
    fn apply_application(&self, destination_namespace: &str) {
        let manifest = tenant_application_manifest(
            &self.repo.display().to_string(),
            TENANT_NAMESPACE,
            "in-cluster",
            destination_namespace,
            Some(SERVICE_ACCOUNT),
        );
        self.apply(&manifest);
    }

    /// Applies an `Application` in `namespace`, targeting a remote cluster.
    fn apply_application_on(&self, cluster: &str, destination_namespace: &str, namespace: &str) {
        // A control-plane-owned Application carries no `serviceAccountName`: it deploys as the
        // credential in the cluster `Secret`, which is the operator's own identity.
        let manifest = tenant_application_manifest(
            &self.repo.display().to_string(),
            namespace,
            cluster,
            destination_namespace,
            None,
        );
        self.apply(&manifest);
    }

    fn apply(&self, manifest: &str) {
        // Re-creating the object keeps the test independent of whatever a previous run left behind
        // (a finalizer would otherwise keep it `Terminating`).
        for namespace in [TENANT_NAMESPACE, CONTROL_NAMESPACE] {
            let _ = kubectl(&[
                "-n",
                namespace,
                "delete",
                "application",
                APPLICATION_NAME,
                "--ignore-not-found=true",
                "--timeout=120s",
            ]);
        }
        apply_manifest(manifest);
    }

    /// Runs one reconcile exactly as the controller's finalizer gate would.
    async fn reconcile(&self) -> Result<(), ferriscd_controller::reconcile::ControllerError> {
        let app = self.read_application().await;
        ferriscd_controller::reconcile::reconcile_instance(Arc::new(app), self.ctx.clone())
            .await
            .map(|_action| ())
    }

    async fn read_application(&self) -> Application {
        for namespace in [TENANT_NAMESPACE, CONTROL_NAMESPACE] {
            if let Ok(app) = Api::<Application>::namespaced(self.client.clone(), namespace)
                .get(APPLICATION_NAME)
                .await
            {
                return app;
            }
        }
        panic!("the Application must exist in {TENANT_NAMESPACE} or {CONTROL_NAMESPACE}");
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

/// A kind the project's `namespaceResourceWhitelist` deliberately does **not** include (case 1b).
fn deployment_manifest(namespace: &str) -> String {
    format!(
        r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {APPLICATION_NAME}
  namespace: {namespace}
spec:
  replicas: 1
  selector:
    matchLabels: {{app: {APPLICATION_NAME}}}
  template:
    metadata:
      labels: {{app: {APPLICATION_NAME}}}
    spec:
      containers:
        - name: app
          image: registry.k8s.io/pause:3.9
"#
    )
}

/// The project the whole suite uses.
///
/// It deliberately lists `kube-system` as a **destination** (so case 2b can only be refused by the
/// API server) while its kind whitelist is a single entry (so case 1b is refused by the project),
/// and it lists both the tenant namespace and the control-plane namespace as sources.
fn project_manifest() -> String {
    format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {PROJECT}
  namespace: {CONTROL_NAMESPACE}
spec:
  description: v0.5 enterprise acceptance fixture
  sourceRepos:
    - "*"
  sourceNamespaces:
    - {TENANT_NAMESPACE}
    - {CONTROL_NAMESPACE}
  destinations:
    - cluster: in-cluster
      namespace: {DESTINATION_NAMESPACE}
    # Permitted on purpose: case 2b must be refused by the API server, not by the project.
    - cluster: in-cluster
      namespace: {FORBIDDEN_NAMESPACE}
    - cluster: {REMOTE_CLUSTER}
      namespace: {REMOTE_NAMESPACE}
  # Nothing cluster-scoped: an escalation attempt is a project denial, not an RBAC surprise.
  clusterResourceWhitelist: []
  namespaceResourceWhitelist:
    - group: ""
      kind: ConfigMap
  allowedServiceAccounts:
    - {DESTINATION_NAMESPACE}/{SERVICE_ACCOUNT}
"#
    )
}

/// The restricted `ServiceAccount` and its **group** `RoleBinding` (finding H5).
///
/// The subject is `Group: system:serviceaccounts:enterprise-app`, which no request satisfies by user
/// name alone: the `Impersonate-Group` headers are what make the binding apply.
fn tenant_rbac_manifest() -> String {
    format!(
        r#"apiVersion: v1
kind: ServiceAccount
metadata:
  name: {SERVICE_ACCOUNT}
  namespace: {DESTINATION_NAMESPACE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: enterprise-configmap-writer
  namespace: {DESTINATION_NAMESPACE}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: enterprise-configmap-writer
  namespace: {DESTINATION_NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: enterprise-configmap-writer
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: {TENANT_GROUP}
"#
    )
}

/// An `Application` in `namespace` targeting `cluster`/`destination_namespace`.
fn tenant_application_manifest(
    repo_url: &str,
    namespace: &str,
    cluster: &str,
    destination_namespace: &str,
    service_account: Option<&str>,
) -> String {
    let service_account_line = match service_account {
        Some(name) => format!("  serviceAccountName: {name}\n"),
        None => String::new(),
    };
    format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {APPLICATION_NAME}
  namespace: {namespace}
spec:
  project: {PROJECT}
{service_account_line}  source:
    git:
      repoURL: {repo_url}
      targetRevision: main
      path: .
  destination:
    cluster: {cluster}
    namespace: {destination_namespace}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
  requeueAfterSeconds: 15
"#
    )
}

/// Builds a `ferriscd.io/secret-type=cluster` `Secret` from a kubeconfig context.
///
/// Reads the context's own server, CA bundle and credentials (bearer token or client certificate)
/// through `kubectl config view --raw`, which is what an operator copies into the `Secret` anyway.
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
                .unwrap_or_else(|| panic!("the kubeconfig user needs a bearer token or {field}"));
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

/// Deletes everything this suite creates, even when an assertion panics.
struct ClusterCleanup;

impl ClusterCleanup {
    fn new() -> Self {
        Self::delete_all();
        Self
    }

    fn delete_all() {
        for namespace in [TENANT_NAMESPACE, CONTROL_NAMESPACE] {
            let _ = kubectl(&[
                "-n",
                namespace,
                "delete",
                "application",
                APPLICATION_NAME,
                "--ignore-not-found=true",
                "--timeout=120s",
            ]);
        }
        for namespace in [DESTINATION_NAMESPACE, DENIED_NAMESPACE] {
            let _ = kubectl(&[
                "delete",
                "configmap",
                CONFIGMAP_NAME,
                "-n",
                namespace,
                "--ignore-not-found=true",
            ]);
            let _ = kubectl(&[
                "delete",
                "deployment",
                APPLICATION_NAME,
                "-n",
                namespace,
                "--ignore-not-found=true",
            ]);
        }
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "secret",
            REMOTE_CLUSTER,
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "delete",
            "appproject",
            PROJECT,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "--context",
            REMOTE_CONTEXT,
            "-n",
            REMOTE_NAMESPACE,
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

/// Removes one leader-election `Lease` between runs.
struct LeaseCleanup {
    lease: String,
}

impl LeaseCleanup {
    fn new(lease: &str) -> Self {
        let cleanup = Self {
            lease: lease.to_owned(),
        };
        cleanup.delete();
        cleanup
    }

    fn delete(&self) {
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "lease",
            &self.lease,
            "--ignore-not-found=true",
        ]);
    }
}

impl Drop for LeaseCleanup {
    fn drop(&mut self) {
        self.delete();
    }
}

async fn live_client() -> kube::Client {
    ensure_crypto_provider();
    let config = kube::Config::infer()
        .await
        .expect("kubeconfig must point at the kind cluster");
    kube::Client::try_from(config).expect("kube client")
}

/// Safety rail (AGENTS.md): never run a live test against a non-`kind` context.
fn require_kind_context() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
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

fn configmap_exists(namespace: &str, name: &str) -> bool {
    kubectl(&["get", "configmap", name, "-n", namespace, "-o", "name"])
        .status
        .success()
}

fn configmap_exists_on(context: &str, namespace: &str) -> bool {
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

/// Whether the `Application` carries the FerrisCD finalizer.
fn has_finalizer(app: &Application) -> bool {
    app.metadata.finalizers.as_ref().is_some_and(|finalizers| {
        finalizers
            .iter()
            .any(|item| item == ferriscd_controller::reconcile::FINALIZER)
    })
}

/// The `status.sync.status` of an `Application` status.
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
