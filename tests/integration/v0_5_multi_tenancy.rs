//! Live `v0.5` multi-tenancy test: a tenant `Application` reconciled **as its own
//! ServiceAccount** (`T12.2` + `T12.3`).
//!
//! # Safety gate
//!
//! This test **must never touch a non-`kind` cluster**. The first thing it does is assert that
//! `kubectl config current-context` starts with `kind-`, mirroring the `test-integration`
//! Makefile guard. It is `#[ignore]`d so `make gate` never runs it (and never needs a cluster);
//! invoke it explicitly:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-controller --test v0_5_multi_tenancy -- --ignored
//! ```
//!
//! # What this pins (and the hermetic tests cannot)
//!
//! 1. **Refusal.** A tenant `Application` (`team-a`) with no `spec.serviceAccountName` is denied
//!    with `Ready=False, reason=PolicyViolation`, and nothing is deployed.
//! 2. **Authorization.** With `AppProject.spec.sourceNamespaces: ["team-a"]` and an allowed
//!    `serviceAccountName`, the same `Application` syncs: `status.sync.status=Synced`, a `Ready`
//!    condition is written, and the **finalizer lands in `team-a`** (not in the control-plane
//!    namespace).
//! 3. **Impersonation is real.** A restricted `ServiceAccount` bound through a **group**
//!    `RoleBinding` (`system:serviceaccounts:tenant-a`) can write a `ConfigMap` into its own
//!    namespace — which only works if `Impersonate-Group` is sent (finding H5) — while a
//!    `ConfigMap` into `kube-system` and a `ClusterRole` are refused by the **API server** with
//!    `403 Forbidden` naming `system:serviceaccount:tenant-a:deployer`. The project deliberately
//!    allows both, so the denial can only come from the impersonation.
//!
//! Hermetic coverage of the same rules (header construction, pool reuse, policy ordering,
//! phase preservation) lives in `crates/ferriscd-controller/src/impersonation.rs` and
//! `crates/ferriscd-controller/src/sync.rs`.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use ferriscd_controller::discovery::DiscoveryCache;
use ferriscd_controller::dry_run::DynamicDryRunApi;
use ferriscd_controller::impersonation::{
    ImpersonatingAccess, ImpersonationPool, ensure_crypto_provider,
};
use ferriscd_controller::live_state::DynamicApiSource;
use ferriscd_controller::reconcile::{ApiStatusWriter, ReconcileContext, reconcile_instance};
use ferriscd_controller::sync::{DynamicApiApplier, InventorySyncPipeline};
use ferriscd_controller::{ApiProjectSource, ApplicationNamespaces, ApplicationScope};
use ferriscd_crd::Application;
use ferriscd_crd::status::{ApplicationStatus, CONDITION_READY, ConditionStatus, SyncStatus};
use ferriscd_engine::repo::{
    GixGitClient, GixGitClientConfig, RepoCache, RepoCacheConfig, RepoUrlPolicy,
};
use kube::Api;

/// Control-plane namespace (owns the `AppProject`).
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Namespace the tenant `Application` lives in.
const TENANT_NAMESPACE: &str = "team-a";
/// Namespace the tenant deploys into (its own, restricted by RBAC).
const DESTINATION_NAMESPACE: &str = "tenant-a";
/// The namespace the tenant must **not** be able to write to.
const FORBIDDEN_NAMESPACE: &str = "kube-system";
/// `Application` name.
const APPLICATION_NAME: &str = "tenant-app";
/// The restricted `ServiceAccount` the tenant deploys as.
const SERVICE_ACCOUNT: &str = "deployer";
/// The impersonated user the API server must name in its `403`s.
const IMPERSONATED_USER: &str = "system:serviceaccount:tenant-a:deployer";
/// Group the `RoleBinding` grants through: only `Impersonate-Group` can satisfy this (finding H5).
const TENANT_GROUP: &str = "system:serviceaccounts:tenant-a";
/// Finalizer the controller owns.
const FINALIZER: &str = "ferriscd.io/finalizer";
/// The ConfigMap every commit declares.
const CONFIGMAP_NAME: &str = "tenant-settings";

#[tokio::test]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn a_tenant_application_is_refused_without_a_service_account_and_impersonated_with_one() {
    // Safety rail (AGENTS.md): never run a live test against a non-`kind` context.
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace(TENANT_NAMESPACE);
    ensure_namespace(DESTINATION_NAMESPACE);
    let _cleanup = ClusterCleanup::new();
    apply_manifest(&tenant_project_manifest());
    apply_manifest(&tenant_rbac_manifest());

    let fixture = Fixture::new().await;

    // -----------------------------------------------------------------
    // (a) A tenant Application without `serviceAccountName` is refused
    // -----------------------------------------------------------------
    fixture.commit(&[("configmap.yaml", configmap_manifest(DESTINATION_NAMESPACE))]);
    fixture.apply_application(None);

    let err = fixture.reconcile().await.expect_err(
        "a tenant Application without a ServiceAccount must be denied (never deployed as the \
         controller)",
    );
    let message = err.to_string();
    assert!(
        message.contains("serviceAccountName"),
        "the denial must name the missing field: {message}"
    );
    assert!(
        !configmap_exists(DESTINATION_NAMESPACE, CONFIGMAP_NAME),
        "a denied Application must deploy nothing"
    );

    let status = fixture.read_status().await;
    let ready = status
        .condition(CONDITION_READY)
        .expect("the denial must still patch /status (always-update-status)");
    assert_eq!(
        ready.reason, "PolicyViolation",
        "a tenancy denial is a PolicyViolation, not a generic sync error: {ready:?}"
    );
    assert_eq!(ready.status, ConditionStatus::False);

    // -----------------------------------------------------------------
    // (b) With an authorized ServiceAccount it reconciles — as that ServiceAccount
    // -----------------------------------------------------------------
    fixture.apply_application(Some(SERVICE_ACCOUNT));
    fixture
        .reconcile()
        .await
        .expect("an authorized tenant Application must reconcile");

    let status = fixture.read_status().await;
    assert_eq!(
        sync_status(&status),
        Some(SyncStatus::Synced),
        "the tenant Application must sync: {status:?}"
    );
    let ready = status
        .condition(CONDITION_READY)
        .expect("a Ready condition is written on success too");
    assert_eq!(
        ready.status,
        ConditionStatus::True,
        "a successful tenant reconcile is Ready=True: {ready:?}"
    );
    assert!(
        configmap_exists(DESTINATION_NAMESPACE, CONFIGMAP_NAME),
        "the ConfigMap must be applied into the tenant namespace (as the ServiceAccount, which is \
         the only identity bound to it)"
    );

    // The finalizer has to land on the object the controller was handed, i.e. in `team-a`.
    assert!(
        has_finalizer(&fixture.read_application().await),
        "the finalizer must be added to the Application in {TENANT_NAMESPACE}, not in \
         {CONTROL_NAMESPACE}"
    );

    // -----------------------------------------------------------------
    // (c) The API server — not the policy — refuses what the tenant may not do
    // -----------------------------------------------------------------
    // The project explicitly allows `kube-system` and cluster-scoped `ClusterRole`, so a `403`
    // here can only come from the impersonated ServiceAccount's own RBAC.
    fixture.commit(&[("configmap.yaml", configmap_manifest(FORBIDDEN_NAMESPACE))]);
    let err = fixture
        .reconcile()
        .await
        .expect_err("the tenant must not be able to write into kube-system");
    let message = err.to_string();
    assert!(
        message.contains("forbidden") || message.contains("403"),
        "expected an API-server denial, got: {message}"
    );
    assert!(
        message.contains(IMPERSONATED_USER),
        "the denial must name the impersonated ServiceAccount: {message}"
    );
    assert!(
        !configmap_exists(FORBIDDEN_NAMESPACE, CONFIGMAP_NAME),
        "nothing may be created in {FORBIDDEN_NAMESPACE}"
    );

    fixture.commit(&[("clusterrole.yaml", cluster_role_manifest())]);
    let err = fixture
        .reconcile()
        .await
        .expect_err("the tenant must not be able to create a ClusterRole");
    let message = err.to_string();
    assert!(
        message.contains("forbidden") || message.contains("403"),
        "expected an API-server denial, got: {message}"
    );
    assert!(
        message.contains(IMPERSONATED_USER),
        "the denial must name the impersonated ServiceAccount: {message}"
    );
    assert!(
        !kubectl(&["get", "clusterrole", "tenant-escalation", "-o", "name"])
            .status
            .success(),
        "the ClusterRole must not exist"
    );
}

// ---------------------------------------------------------------------------
// Controller wiring
// ---------------------------------------------------------------------------

/// The production wiring of `ferriscd controller` (`run_with`), for one test process.
struct Fixture {
    client: kube::Client,
    ctx: Arc<ReconcileContext>,
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
        // `T12.3`: one shared connector, exactly like the binary builds.
        let pool = ImpersonationPool::new(&kube_config).expect("impersonation pool");
        assert_eq!(pool.connectors(), 1, "the pool owns exactly one connector");
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
            .with_impersonation_source(Arc::new(ImpersonatingAccess::new(Arc::new(pool)))),
        );
        let apps_api = Api::<Application>::namespaced(client.clone(), CONTROL_NAMESPACE);
        let status = Arc::new(ApiStatusWriter::new(apps_api.clone()).with_client(client.clone()));
        let ctx =
            Arc::new(ReconcileContext::new(apps_api, pipeline, status).with_client(client.clone()));

        Self {
            client,
            ctx,
            repo,
            _temp: temp,
        }
    }

    /// Writes `files` and commits them, replacing the previous tree.
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

    /// Applies (or re-creates) the tenant `Application` with the given ServiceAccount.
    fn apply_application(&self, service_account: Option<&str>) {
        let manifest =
            tenant_application_manifest(&self.repo.display().to_string(), service_account);
        // Strip the finalizer first because this in-process test does not run a background watch
        // loop to clear `ferriscd.io/finalizer` during `kubectl delete`.
        let _ = kubectl(&[
            "-n",
            TENANT_NAMESPACE,
            "patch",
            "application",
            APPLICATION_NAME,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":[]}}"#,
        ]);
        let _ = kubectl(&[
            "-n",
            TENANT_NAMESPACE,
            "delete",
            "application",
            APPLICATION_NAME,
            "--ignore-not-found=true",
            "--timeout=30s",
        ]);
        apply_manifest(&manifest);
    }

    /// Runs reconcile through the controller's finalizer gate: when the `Application` does not yet
    /// carry `ferriscd.io/finalizer`, the first `reconcile_instance` call only attaches it, so a
    /// second call runs `Apply` against the persisted object.
    async fn reconcile(&self) -> Result<(), ferriscd_controller::reconcile::ControllerError> {
        let app = self.read_application().await;
        let had_finalizer = has_finalizer(&app);
        reconcile_instance(Arc::new(app), self.ctx.clone()).await?;
        if !had_finalizer {
            let app = self.read_application().await;
            reconcile_instance(Arc::new(app), self.ctx.clone()).await?;
        }
        Ok(())
    }

    async fn read_application(&self) -> Application {
        Api::<Application>::namespaced(self.client.clone(), TENANT_NAMESPACE)
            .get(APPLICATION_NAME)
            .await
            .expect("the tenant Application must exist")
    }

    async fn read_status(&self) -> ApplicationStatus {
        self.read_application().await.status.unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Manifests
// ---------------------------------------------------------------------------

/// A project that authorizes `team-a` and its ServiceAccount — and deliberately also authorizes
/// `kube-system` and `ClusterRole`, so step (c) can only be refused by the API server.
fn tenant_project_manifest() -> String {
    format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: tenant
  namespace: {CONTROL_NAMESPACE}
spec:
  description: v0.5 multi-tenancy fixture
  sourceRepos:
    - "*"
  sourceNamespaces:
    - {TENANT_NAMESPACE}
  destinations:
    - cluster: in-cluster
      namespace: {DESTINATION_NAMESPACE}
    - cluster: in-cluster
      namespace: {FORBIDDEN_NAMESPACE}
  clusterResourceWhitelist:
    - group: rbac.authorization.k8s.io
      kind: ClusterRole
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
  allowedServiceAccounts:
    - {DESTINATION_NAMESPACE}/{SERVICE_ACCOUNT}
"#
    )
}

/// The restricted `ServiceAccount` and a **group** `RoleBinding` (finding H5).
///
/// The binding names `Group: system:serviceaccounts:tenant-a`, which no request can satisfy by
/// user name alone: the `Impersonate-Group` headers are what make it apply.
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
  name: tenant-configmap-writer
  namespace: {DESTINATION_NAMESPACE}
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list", "watch", "create", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: tenant-configmap-writer
  namespace: {DESTINATION_NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: tenant-configmap-writer
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: Group
    name: {TENANT_GROUP}
"#
    )
}

fn configmap_manifest(namespace: &str) -> String {
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {CONFIGMAP_NAME}\n  namespace: {namespace}\ndata:\n  key: value\n"
    )
}

fn cluster_role_manifest() -> String {
    "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: tenant-escalation\nrules:\n  - apiGroups: [\"*\"]\n    resources: [\"*\"]\n    verbs: [\"*\"]\n".to_owned()
}

fn tenant_application_manifest(repo_url: &str, service_account: Option<&str>) -> String {
    let service_account_line = match service_account {
        Some(name) => format!("  serviceAccountName: {name}\n"),
        None => String::new(),
    };
    format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {APPLICATION_NAME}
  namespace: {TENANT_NAMESPACE}
spec:
  project: tenant
{service_account_line}  source:
    git:
      repoURL: {repo_url}
      targetRevision: main
      path: .
  destination:
    cluster: in-cluster
    namespace: {DESTINATION_NAMESPACE}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
  requeueAfterSeconds: 15
"#
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
            TENANT_NAMESPACE,
            "patch",
            "application",
            APPLICATION_NAME,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":[]}}"#,
        ]);
        let _ = kubectl(&[
            "-n",
            TENANT_NAMESPACE,
            "delete",
            "application",
            APPLICATION_NAME,
            "--ignore-not-found=true",
            "--timeout=30s",
        ]);
        let _ = kubectl(&[
            "delete",
            "clusterrole",
            "tenant-escalation",
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "delete",
            "appproject",
            "tenant",
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "delete",
            "configmap",
            CONFIGMAP_NAME,
            "-n",
            DESTINATION_NAMESPACE,
            "--ignore-not-found=true",
        ]);
    }
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        Self::delete_all();
    }
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
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating namespace {namespace} failed: {}",
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

/// Whether the `Application` carries the FerrisCD finalizer.
fn has_finalizer(app: &Application) -> bool {
    app.metadata
        .finalizers
        .as_ref()
        .is_some_and(|finalizers| finalizers.iter().any(|item| item == FINALIZER))
}

/// The `status.sync.status` of an `Application` status.
fn sync_status(status: &ApplicationStatus) -> Option<SyncStatus> {
    status.sync.as_ref().map(|sync| sync.status)
}

fn current_kube_context() -> String {
    let output = Command::new("kubectl")
        .args(["config", "current-context"])
        .output()
        .expect("kubectl config current-context must run");
    assert!(
        output.status.success(),
        "kubectl config current-context failed: {}",
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
