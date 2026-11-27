//! Live `v0.5` test for Kubernetes Secret-backed Git repository credentials (`T12.4`).
//!
//! # Safety gate
//!
//! This test **must never touch a non-`kind` cluster**. The first thing it does is assert that
//! `kubectl config current-context` starts with `kind-`, mirroring the `test-integration` Makefile
//! guard. It is `#[ignore]`d so `make gate` never runs it (and never needs a cluster); invoke it
//! explicitly:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-controller --test v0_5_repo_credentials -- --ignored
//! ```
//!
//! # What this pins (and the hermetic unit tests cannot)
//!
//! 1. **The store against a real API server.** A `ferriscd.io/secret-type=repository` `Secret` in
//!    `ferriscd-system` is listed (namespaced + label-filtered), parsed, and matched to a
//!    repository URL prefix; the same `Secret` placed in another namespace, or without the label,
//!    is invisible — there is no cluster-wide `Secret` read that could find them.
//! 2. **The wired pipeline.** Reconciling an `Application` whose `spec.source.git.repoUrl` falls
//!    under a credential's prefix resolves that credential *and* hands it to the Git client, which
//!    is observable in the logs (the matched `Secret` is named) — while neither the token nor the
//!    user name ever appears in the logs or in `/status`.
//! 3. **No regression for public repositories.** An `Application` whose URL matches no `Secret`
//!    still syncs anonymously.
//! 4. **A malformed `Secret` is terminal**, names the `Secret`, and leaks nothing.
//!
//! # Why there is no token-protected local Git HTTP fixture here (`T12.4` deviation)
//!
//! The roadmap text suggests reconciling against a token-protected local Git HTTP fixture. The
//! **certificate is not the blocker**: a loopback HTTPS server with a throwaway certificate can be
//! trusted by this stack through the platform trust store (`SSL_CERT_FILE` for the rustls/`reqwest`
//! transport), so `https://127.0.0.1:<port>` is reachable in principle. (`gix`'s per-request
//! TLS knobs — `http.sslVerify`/`http.sslCAInfo` — are only honoured by the `curl` backend, which
//! is why the trust has to come from the environment rather than from repository config.)
//!
//! What is missing is an **HTTPS Git server in the harness**. Nothing in this repository serves
//! (or takes a dependency on) an authenticated Git smart-HTTP endpoint, and writing one — TLS
//! listener, `git http-backend`, per-request basic auth — is test infrastructure of its own rather
//! than a test. That is recorded as an explicit follow-up (lesson 12, §9) instead of being worked
//! around by weakening a production invariant.
//!
//! Plaintext `http://` remains out of reach for a different reason — a deliberate security
//! boundary — and stays pinned as such by three independent layers:
//!
//! * `ferriscd_engine::repo::validate_repo_url` accepts only `https://`, `ssh://` and SCP-style
//!   SSH remotes (plus `file://` under the test/local policy): a plaintext `http://` remote never
//!   reaches a transport.
//! * `isolated_open_options` pins `protocol.http.allow=never` on every mirror, even when the
//!   permissive URL policy is selected.
//! * `gix`'s HTTP transport refuses to put credentials on the wire in clear text
//!   (`AuthenticationRefused: Will not send credentials in clear text over http`) unless the
//!   workspace enables `http-client-insecure-credentials` — a compile-time switch that would
//!   weaken **production** builds of the engine.
//!
//! The credential path is therefore verified in two honest halves today: the *mapping and
//! matching* hermetically in `ferriscd_controller::credentials`, the *"resolved credentials really
//! reach the Git client"* seam hermetically through `FakeGitClient::credential_log` in
//! `ferriscd_controller::sync`, and the *Kubernetes + pipeline + hygiene* end to end here. The
//! clear-text-refusal is itself pinned by `a_plaintext_http_remote_never_reaches_a_transport`.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use ferriscd_controller::ApiProjectSource;
use ferriscd_controller::credentials::{CredentialSource, SecretCredentialStore};
use ferriscd_controller::discovery::DiscoveryCache;
use ferriscd_controller::dry_run::DynamicDryRunApi;
use ferriscd_controller::live_state::DynamicApiSource;
use ferriscd_controller::reconcile::{ApiStatusWriter, ReconcileContext, reconcile_instance};
use ferriscd_controller::sync::{DynamicApiApplier, InventorySyncPipeline};
use ferriscd_crd::Application;
use ferriscd_crd::status::{ApplicationStatus, CONDITION_READY, ConditionStatus, SyncStatus};
use ferriscd_engine::repo::{
    GixGitClient, GixGitClientConfig, RepoCache, RepoCacheConfig, RepoCredentials, RepoUrlPolicy,
};
use kube::Api;

/// Control-plane namespace: the only place a credential `Secret` is ever read from.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Namespace the fixture `Application` deploys into.
const DESTINATION_NAMESPACE: &str = "repo-creds-demo";
/// `Application` name used for the credentialed attempt.
const APPLICATION_NAME: &str = "credentialed-app";
/// `Application` name used for the anonymous (local fixture) sync.
const ANONYMOUS_APPLICATION_NAME: &str = "anonymous-app";
/// The credential `Secret` in the control plane.
const SECRET_NAME: &str = "repo-creds";
/// The `Secret` that only exists in the tenant namespace (must be ignored).
const TENANT_SECRET_NAME: &str = "tenant-repo-creds";
/// The control-plane `Secret` without the repository label (must be ignored).
const UNLABELED_SECRET_NAME: &str = "unlabeled-repo-creds";
/// The `Secret` that is deliberately misconfigured (must be a terminal error).
const MALFORMED_SECRET_NAME: &str = "broken-repo-creds";
/// Basic-auth user the fixture `Secret` declares.
const FIXTURE_USER: &str = "ferriscd-bot";
/// Basic-auth token the fixture `Secret` declares. Distinctive enough to search logs for.
const FIXTURE_TOKEN: &str = "s3cr3t-token-value-never-logged";
/// Repository URL the credential matches (`git.invalid` is reserved and never resolves, so the
/// clone fails at the network boundary — *after* the credential was resolved and handed over).
const CREDENTIALED_REPO_URL: &str = "https://git.invalid/ferriscd/repo.git";
/// Repository URL on the same host that does **not** fall under the credential's prefix.
const UNMATCHED_REPO_URL: &str = "https://git.invalid/other/repo.git";
/// Repository URL whose only `Secret` lives in the tenant namespace.
const TENANT_ONLY_REPO_URL: &str = "https://tenant-only.invalid/ferriscd/repo.git";
/// The ConfigMap the local fixture commit declares.
const CONFIGMAP_NAME: &str = "credentialed-settings";

#[tokio::test]
#[ignore = "requires a live kind cluster (make kind-up)"]
async fn control_plane_secrets_supply_repository_credentials_without_leaking_them() {
    // Safety rail (AGENTS.md): never run a live test against a non-`kind` context.
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    let logs = capture_logs();
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace(DESTINATION_NAMESPACE);
    apply_manifest(&default_project_manifest());
    let _cleanup = ClusterCleanup::new();

    // -----------------------------------------------------------------
    // (a) The store, against the real API server
    // -----------------------------------------------------------------
    apply_manifest(&credential_secret_manifest());
    // The same shape of credential advertised from the tenant namespace: must be invisible.
    apply_manifest(&tenant_namespace_secret_manifest());
    // A `Secret` in the control plane *without* the label: must also be invisible.
    apply_manifest(&unlabeled_secret_manifest());

    let harness = Harness::new().await;
    let store = SecretCredentialStore::new(harness.client.clone(), CONTROL_NAMESPACE);

    assert_eq!(
        store
            .credentials_for(CREDENTIALED_REPO_URL)
            .await
            .expect("the labeled Secret must be usable"),
        RepoCredentials::HttpBasic {
            username: FIXTURE_USER.to_owned(),
            password: FIXTURE_TOKEN.to_owned(),
        },
        "the control-plane Secret must supply the credentials of its url prefix"
    );
    assert_eq!(
        store
            .credentials_for(UNMATCHED_REPO_URL)
            .await
            .expect("an unmatched repository is anonymous, not an error"),
        RepoCredentials::Anonymous,
        "a URL outside the prefix (and an unlabeled Secret) must not match"
    );
    assert_eq!(
        store
            .credentials_for(TENANT_ONLY_REPO_URL)
            .await
            .expect("an unmatched repository is anonymous"),
        RepoCredentials::Anonymous,
        "a Secret in the tenant namespace must be invisible: credentials are read from \
         {CONTROL_NAMESPACE} only"
    );

    // A malformed Secret in the control plane is a terminal error that names the Secret.
    apply_manifest(&malformed_secret_manifest());
    let err = store
        .credentials_for(CREDENTIALED_REPO_URL)
        .await
        .expect_err("an unusable Secret must stop credential resolution");
    let terminal = err.failure_class();
    let message = err.to_string();
    assert!(
        message.contains(MALFORMED_SECRET_NAME) && message.contains(CONTROL_NAMESPACE),
        "the error must name the Secret and its namespace: {message}"
    );
    assert!(!message.contains("this-secret-has-no-url"), "{message}");
    assert_eq!(
        terminal,
        ferriscd_controller::FailureClass::Terminal,
        "a Secret only the operator can fix must not be retried forever: {err}"
    );
    delete_secret(CONTROL_NAMESPACE, MALFORMED_SECRET_NAME);

    // -----------------------------------------------------------------
    // (b) The pipeline: the credential is resolved, used, and never logged
    // -----------------------------------------------------------------
    harness.apply_application(APPLICATION_NAME, CREDENTIALED_REPO_URL);
    harness
        .reconcile(APPLICATION_NAME)
        .await
        .expect_err("git.invalid never resolves, so the clone must fail");

    let log_text = captured(&logs);
    assert!(
        log_text.contains("resolved repository credentials"),
        "the credential path must be observable — otherwise the assertions below mean nothing: \
         {log_text}"
    );
    assert!(
        log_text.contains(SECRET_NAME),
        "the matched Secret must be named so a mismatch is debuggable: {log_text}"
    );
    for secret in [FIXTURE_TOKEN, FIXTURE_USER] {
        assert!(
            !log_text.contains(secret),
            "{secret} must never reach the logs: {log_text}"
        );
    }

    let status = harness.read_status(APPLICATION_NAME).await;
    let rendered_status = format!("{status:?}");
    for secret in [FIXTURE_TOKEN, FIXTURE_USER] {
        assert!(
            !rendered_status.contains(secret),
            "{secret} must never reach /status: {rendered_status}"
        );
    }
    let ready = status
        .condition(CONDITION_READY)
        .expect("always-update-status: a failed pass still patches /status");
    assert_eq!(
        ready.status,
        ConditionStatus::False,
        "a failed clone is not Ready: {ready:?}"
    );
    assert_ne!(
        sync_status(&status),
        Some(SyncStatus::Synced),
        "nothing may be reported as synced: {status:?}"
    );

    // -----------------------------------------------------------------
    // (c) No regression: an unmatched repository still syncs anonymously
    // -----------------------------------------------------------------
    let temp = tempfile::TempDir::new().expect("create the local fixture directory");
    let repo = temp.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create the local fixture repository");
    git(&repo, &["init", "--initial-branch=main"]);
    std::fs::write(
        repo.join("configmap.yaml"),
        configmap_manifest(DESTINATION_NAMESPACE),
    )
    .expect("write the fixture manifest");
    git(&repo, &["add", "--all"]);
    git(
        &repo,
        &[
            "-c",
            "user.name=FerrisCD Test",
            "-c",
            "user.email=ferriscd@example.com",
            "commit",
            "-m",
            "fixture",
        ],
    );

    harness.apply_application(ANONYMOUS_APPLICATION_NAME, &repo.display().to_string());
    harness
        .reconcile(ANONYMOUS_APPLICATION_NAME)
        .await
        .expect("a repository without a matching Secret must still sync");

    let status = harness.read_status(ANONYMOUS_APPLICATION_NAME).await;
    assert_eq!(
        sync_status(&status),
        Some(SyncStatus::Synced),
        "wiring the credential store must not break anonymous repositories: {status:?}"
    );
    assert!(
        configmap_exists(DESTINATION_NAMESPACE, CONFIGMAP_NAME),
        "the anonymous sync must have applied the manifest"
    );
    assert!(
        captured(&logs).contains("no repository credential Secret matched"),
        "the unmatched path must be explicit in the logs"
    );
}

// ---------------------------------------------------------------------------
// The controller wiring
// ---------------------------------------------------------------------------

/// The production wiring of `ferriscd controller` (`run_with`), for one test process.
struct Harness {
    client: kube::Client,
    ctx: Arc<ReconcileContext>,
    _temp: tempfile::TempDir,
}

impl Harness {
    async fn new() -> Self {
        ferriscd_controller::impersonation::ensure_crypto_provider();
        let kube_config = kube::Config::infer()
            .await
            .expect("kubeconfig must point at the kind cluster");
        let client = kube::Client::try_from(kube_config).expect("kube client");

        let temp = tempfile::TempDir::new().expect("create the work root");
        let work_root = temp.path().join("work");
        let repos = Arc::new(RepoCache::new(
            Arc::new(GixGitClient::new(
                GixGitClientConfig::new()
                    // The local `file://` fixture in step (c) needs the test/local policy.
                    .with_url_policy(RepoUrlPolicy::AllowLocal)
                    .with_work_root(&work_root),
            )),
            RepoCacheConfig::new(&work_root),
        ));
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
            // `T12.4`: the store under test, wired exactly like `run_with` wires it.
            .with_credential_source(Arc::new(SecretCredentialStore::new(
                client.clone(),
                CONTROL_NAMESPACE,
            ))),
        );
        let apps_api = Api::<Application>::namespaced(client.clone(), CONTROL_NAMESPACE);
        let status = Arc::new(ApiStatusWriter::new(apps_api.clone()).with_client(client.clone()));
        let ctx =
            Arc::new(ReconcileContext::new(apps_api, pipeline, status).with_client(client.clone()));

        Self {
            client,
            ctx,
            _temp: temp,
        }
    }

    /// Applies (or re-creates) one fixture `Application`.
    fn apply_application(&self, name: &str, repo_url: &str) {
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "patch",
            "application",
            name,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":[]}}"#,
        ]);
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "application",
            name,
            "--ignore-not-found=true",
            "--timeout=30s",
        ]);
        apply_manifest(&application_manifest(name, repo_url));
    }

    /// Runs reconcile through the controller's finalizer gate: when the `Application` does not yet
    /// carry `ferriscd.io/finalizer`, the first `reconcile_instance` call only attaches it, so a
    /// second call runs `Apply` against the persisted object.
    async fn reconcile(
        &self,
        name: &str,
    ) -> Result<(), ferriscd_controller::reconcile::ControllerError> {
        let app = self.read_application(name).await;
        let had_finalizer = app.metadata.finalizers.as_ref().is_some_and(|finalizers| {
            finalizers
                .iter()
                .any(|item| item == "ferriscd.io/finalizer")
        });
        reconcile_instance(Arc::new(app), self.ctx.clone()).await?;
        if !had_finalizer {
            let app = self.read_application(name).await;
            reconcile_instance(Arc::new(app), self.ctx.clone()).await?;
        }
        Ok(())
    }

    async fn read_application(&self, name: &str) -> Application {
        Api::<Application>::namespaced(self.client.clone(), CONTROL_NAMESPACE)
            .get(name)
            .await
            .expect("the fixture Application must exist")
    }

    async fn read_status(&self, name: &str) -> ApplicationStatus {
        self.read_application(name).await.status.unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Manifests
// ---------------------------------------------------------------------------

/// The shipped `default` project (permissive: every source repo, every destination).
fn default_project_manifest() -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/manifests/default-project.yaml"),
    )
    .expect("the shipped default AppProject must be readable")
}

/// The credential `Secret` in the control-plane namespace: a host-and-path **prefix** template.
fn credential_secret_manifest() -> String {
    format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {SECRET_NAME}
  namespace: {CONTROL_NAMESPACE}
  labels:
    ferriscd.io/secret-type: repository
stringData:
  url: https://git.invalid/ferriscd
  username: {FIXTURE_USER}
  token: {FIXTURE_TOKEN}
"#
    )
}

/// The same credential advertised from the *tenant* namespace, which must be ignored.
fn tenant_namespace_secret_manifest() -> String {
    format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {TENANT_SECRET_NAME}
  namespace: {DESTINATION_NAMESPACE}
  labels:
    ferriscd.io/secret-type: repository
stringData:
  url: https://tenant-only.invalid/ferriscd
  token: wrong-token-from-the-tenant-namespace
"#
    )
}

/// A `Secret` in the control plane that is *not* labeled as a repository credential.
fn unlabeled_secret_manifest() -> String {
    format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {UNLABELED_SECRET_NAME}
  namespace: {CONTROL_NAMESPACE}
stringData:
  url: https://git.invalid/other
  token: unlabeled-token-must-not-be-used
"#
    )
}

/// A labeled `Secret` with no repository URL: unusable, and therefore terminal.
fn malformed_secret_manifest() -> String {
    format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {MALFORMED_SECRET_NAME}
  namespace: {CONTROL_NAMESPACE}
  labels:
    ferriscd.io/secret-type: repository
stringData:
  token: this-secret-has-no-url
"#
    )
}

fn configmap_manifest(namespace: &str) -> String {
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {CONFIGMAP_NAME}\n  namespace: {namespace}\ndata:\n  key: value\n"
    )
}

fn application_manifest(name: &str, repo_url: &str) -> String {
    format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {name}
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
        for name in [APPLICATION_NAME, ANONYMOUS_APPLICATION_NAME] {
            let _ = kubectl(&[
                "-n",
                CONTROL_NAMESPACE,
                "patch",
                "application",
                name,
                "--type=merge",
                "-p",
                r#"{"metadata":{"finalizers":[]}}"#,
            ]);
            let _ = kubectl(&[
                "-n",
                CONTROL_NAMESPACE,
                "delete",
                "application",
                name,
                "--ignore-not-found=true",
                "--timeout=30s",
            ]);
        }
        for name in [SECRET_NAME, MALFORMED_SECRET_NAME, UNLABELED_SECRET_NAME] {
            delete_secret(CONTROL_NAMESPACE, name);
        }
        delete_secret(DESTINATION_NAMESPACE, TENANT_SECRET_NAME);
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

fn delete_secret(namespace: &str, name: &str) {
    let _ = kubectl(&[
        "-n",
        namespace,
        "delete",
        "secret",
        name,
        "--ignore-not-found=true",
    ]);
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

// ---------------------------------------------------------------------------
// Log capture
// ---------------------------------------------------------------------------

/// Shared buffer the test subscriber writes into.
static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

/// Installs a process-wide `tracing` subscriber that records every line into a buffer.
///
/// "Secret values never appear in the logs" is only meaningful if the logs are actually captured;
/// the test therefore asserts both directions — the credential line *is* there, and it carries no
/// secret.
fn capture_logs() -> Arc<Mutex<Vec<u8>>> {
    let buffer = LOGS
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone();
    let writer = LogBuffer(buffer.clone());
    let _ = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .try_init();
    buffer
}

/// Everything captured so far, as text.
fn captured(logs: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&logs.lock().expect("log buffer").clone()).to_string()
}

/// A `MakeWriter` that appends to the shared buffer and never fails.
#[derive(Clone)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut guard) = self.0.lock() {
            guard.extend_from_slice(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
