//! Live `v0.3` end-to-end test: workload **health** on a real `kind` cluster (Phase 09).
//!
//! # Safety gate
//!
//! This test **must never touch a non-`kind` cluster**. The very first thing it does is assert that
//! `kubectl config current-context` starts with `kind-`, mirroring the `test-integration` Makefile
//! guard. It is marked `#[ignore]` so `cargo test` never runs it accidentally; invoke it explicitly
//! with `make test-integration`.
//!
//! # What this pins
//!
//! 1. **`Synced` is not `Healthy`** (`T09.5` trap guard). A `Deployment` whose image tag does not
//!    exist stays `status.sync.status = Synced` (Git and the cluster agree on the spec) while
//!    `status.health.status` moves `Progressing` (the pass that created the object has not observed
//!    it yet) and then `Degraded` (`ProgressDeadlineExceeded`).
//! 2. **Per-resource health is reported.** `status.resources[]` carries the `Deployment`'s GKNN key
//!    together with its verdict and a bounded message.
//! 3. **A fixed image converges.** Pushing a real tag moves health back to `Progressing` and then
//!    `Healthy`, and the controller polls fast (10 s) while it is `Progressing` instead of waiting
//!    for the full `requeueAfterSeconds`.
//!
//! Nothing here was measured before the test was written: every budget is a bound to *check*, and
//! `docs/lessons/09-kubernetes-workload-health-machines.md` §9 records the numbers only once the
//! walkthrough has actually been run by hand.
//!
//! # Why `progressDeadlineSeconds: 45`
//!
//! A `Deployment` only reports `Progressing=False, reason=ProgressDeadlineExceeded` after
//! `spec.progressDeadlineSeconds`, which defaults to **600 s**. The pods of a `Deployment` are not
//! part of the bundle (only the objects Git declares are assessed), so the Deployment's own
//! condition is the signal — and waiting ten minutes for it would make this test useless.
//!
//! # Prerequisites (manual)
//!
//! ```text
//! make kind-up
//! kubectl apply -f deploy/crds
//! ```
//!
//! The test installs the CRDs itself if they are missing, creates the control-plane namespace, and
//! starts/stops the controller binary as a child process.

// Test-only shell-out helpers are allowed to panic: this entire file is compiled as a test
// target and never ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Control-plane namespace the controller watches.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Namespace the `Application` deploys into (declared by a manifest in the fixture repo).
const TARGET_NAMESPACE: &str = "ferriscd-health-demo";
/// `Application` name.
const APPLICATION_NAME: &str = "health-demo";
/// `Deployment` name.
const DEPLOYMENT_NAME: &str = "web";
/// Image tag that cannot be pulled: the `Deployment` will never become available.
const BAD_IMAGE: &str = "nginx:definitely-not-a-real-tag";
/// Image tag that pulls and serves: the rollout converges.
const GOOD_IMAGE: &str = "nginx:1.27-alpine";
/// Short progress deadline so `Degraded` is reachable inside a test (see the module docs).
const PROGRESS_DEADLINE_SECONDS: u32 = 45;

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn health_reports_degraded_for_a_bad_image_and_healthy_after_the_fix() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);

    // Best-effort cleanup even if an assertion below panics.
    let _cluster_cleanup = ClusterCleanup::new();
    let _controller_cleanup = ControllerProcess::start();

    let fixture = tempfile::tempdir().expect("create git fixture directory");
    let repo = fixture.path();
    write_fixture_and_commit(repo, BAD_IMAGE);
    apply_application(repo.to_str().expect("utf8 fixture path"));

    // ---------------------------------------------------------------------
    // 1. bad image: Progressing first (the creating pass has not observed the object)
    // ---------------------------------------------------------------------
    // The `Namespace` is applied before the `Deployment` can be (`DeferredPendingNamespace`), so
    // the first passes may report `Progressing` for that reason too; either way the aggregate must
    // be `Progressing` before it is `Degraded`, which is the assertion that matters.
    wait_for(
        Duration::from_secs(300),
        "the Application to report Progressing",
        || health_status().as_deref() == Some("Progressing"),
    );

    // ---------------------------------------------------------------------
    // 2. bad image: Degraded, while the sync status stays Synced
    // ---------------------------------------------------------------------
    wait_for(
        Duration::from_secs(600),
        "the Application to report Degraded for the bad image",
        || health_status().as_deref() == Some("Degraded"),
    );
    assert_eq!(
        status_jsonpath("{.status.sync.status}"),
        "Synced",
        "Git and the cluster agree on the spec, so the sync status must never be Degraded's \
         business (T09.5): status was {}",
        status_jsonpath("{.status}")
    );
    assert!(
        application_ready(),
        "the Application must still report Ready=True (a degraded workload is not a sync error), \
         got: {}",
        status_jsonpath("{.status.conditions}")
    );
    assert!(
        health_message().contains("progress deadline"),
        "the health message must name the progress deadline, got: {}",
        health_message()
    );
    assert_eq!(
        deployment_resource_health().as_deref(),
        Some("Degraded"),
        "status.resources must carry the per-resource verdict, got: {}",
        status_jsonpath("{.status.resources}")
    );
    assert!(
        deployment_resource_message().contains("progress deadline"),
        "the per-resource message must be actionable, got: {}",
        deployment_resource_message()
    );
    // The pods themselves are `ImagePullBackOff`; the Deployment's own condition is what FerrisCD
    // assesses, but checking the pods documents *why* it is degraded.
    wait_for(
        Duration::from_secs(120),
        "the pod to be ImagePullBackOff",
        || pod_reason().contains("ImagePullBackOff") || pod_reason().contains("ErrImagePull"),
    );

    // ---------------------------------------------------------------------
    // 3. fixed image: Progressing -> Healthy
    // ---------------------------------------------------------------------
    let fixed = fix_image_and_commit(repo, GOOD_IMAGE);
    wait_for(
        Duration::from_secs(300),
        "the fixed revision to sync",
        || synced_revision().as_deref() == Some(fixed.as_str()),
    );
    wait_for(
        Duration::from_secs(600),
        "the Application to report Healthy after the fix",
        || health_status().as_deref() == Some("Healthy"),
    );
    assert_eq!(
        status_jsonpath("{.status.sync.status}"),
        "Synced",
        "the fixed revision must be synced as well"
    );
    assert_eq!(
        deployment_resource_health().as_deref(),
        Some("Healthy"),
        "the per-resource verdict must follow the rollout, got: {}",
        status_jsonpath("{.status.resources}")
    );

    // The adaptive requeue is the observable half of "poll fast while converging": once settled the
    // controller is allowed to wait `requeueAfterSeconds`, so a later pass must still be Healthy
    // (a flapping verdict would break every wave that waits for it in Phase 10).
    let generation = bump_requeue_seconds_and_get_generation();
    wait_for(
        Duration::from_secs(300),
        "a post-convergence pass to keep reporting Healthy",
        || {
            observed_generation() == Some(generation)
                && health_status().as_deref() == Some("Healthy")
        },
    );
}

/// Deletes the resources this test creates.
struct ClusterCleanup;

impl ClusterCleanup {
    fn new() -> Self {
        // Start from a clean slate so a previous aborted run cannot mask a failure.
        let _ = kubectl(&[
            "delete",
            "application",
            APPLICATION_NAME,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "delete",
            "namespace",
            TARGET_NAMESPACE,
            "--ignore-not-found=true",
            // Blocking delete: a namespace left `Terminating` by an earlier run races the next
            // create with `AlreadyExists`/`Forbidden` (finding M2).
            "--timeout=120s",
        ]);
        Self
    }
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        let _ = kubectl(&[
            "delete",
            "application",
            APPLICATION_NAME,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "delete",
            "namespace",
            TARGET_NAMESPACE,
            "--ignore-not-found=true",
            // Blocking delete: a namespace left `Terminating` by an earlier run races the next
            // create with `AlreadyExists`/`Forbidden` (finding M2).
            "--timeout=120s",
        ]);
    }
}

/// Runs `ferriscd controller` for the duration of the test.
struct ControllerProcess {
    child: Child,
}

impl ControllerProcess {
    fn start() -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ferriscd"))
            .args([
                "controller",
                "--namespace",
                CONTROL_NAMESPACE,
                // Explicit opt-in: the fixture repository is a local path, which the production
                // URL policy rejects on purpose.
                "--allow-local-repos",
            ])
            .env("RUST_LOG", "info")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the ferriscd binary must start");
        Self { child }
    }
}

impl Drop for ControllerProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Writes the fixture repository (Namespace + `Deployment`) and commits it.
fn write_fixture_and_commit(repo: &Path, image: &str) -> String {
    write(
        repo,
        "namespace.yaml",
        &format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {TARGET_NAMESPACE}\n"),
    );
    write(repo, "deployment.yaml", &deployment_manifest(image));

    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git_commit(repo, "seed manifests");
    head_sha(repo)
}

/// The `Deployment` manifest with the given image.
///
/// `progressDeadlineSeconds` is deliberately short: it is the only lever that makes a
/// `Deployment`-level `Degraded` observable inside a test (module docs).
fn deployment_manifest(image: &str) -> String {
    format!(
        "apiVersion: apps/v1\n\
         kind: Deployment\n\
         metadata:\n\
         \x20 name: {DEPLOYMENT_NAME}\n\
         spec:\n\
         \x20 replicas: 1\n\
         \x20 progressDeadlineSeconds: {PROGRESS_DEADLINE_SECONDS}\n\
         \x20 selector:\n\
         \x20   matchLabels:\n\
         \x20     app: web\n\
         \x20 template:\n\
         \x20   metadata:\n\
         \x20     labels:\n\
         \x20       app: web\n\
         \x20   spec:\n\
         \x20     containers:\n\
         \x20       - name: web\n\
         \x20         image: {image}\n\
         \x20         ports:\n\
         \x20           - containerPort: 80\n"
    )
}

/// Rewrites the image and commits the change.
fn fix_image_and_commit(repo: &Path, image: &str) -> String {
    write(repo, "deployment.yaml", &deployment_manifest(image));
    git(repo, &["add", "."]);
    git_commit(repo, "fix the image tag");
    head_sha(repo)
}

/// Installs the committed CRDs (idempotent).
fn install_crds() {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package, not this file's
    // directory: this file is `#[path]`-included from
    // `crates/ferriscd-cli/tests/v0_3_health.rs` (the workspace root is a virtual manifest and has
    // no test targets of its own), so the manifest dir is `crates/ferriscd-cli` and `../..` is the
    // workspace root where `deploy/` lives.
    let crds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crds");
    let output = kubectl(&["apply", "-f", &crds.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/crds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Creates `namespace` when it does not exist yet.
fn ensure_namespace(namespace: &str) {
    let manifest = format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n");
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating namespace {namespace} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the `Application` CR that points at the local fixture repository.
///
/// `automated: { selfHeal: true }` is required: the diff gate refuses to apply anything for
/// `automated: None` (manual-only) and, with `selfHeal: false`, only on a source change.
fn apply_application(repo_path: &str) {
    let manifest = format!(
        "apiVersion: ferriscd.io/v1alpha1\n\
         kind: Application\n\
         metadata:\n\
         \x20 name: {APPLICATION_NAME}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         spec:\n\
         \x20 source:\n\
         \x20   git:\n\
         \x20     repoURL: {repo_path}\n\
         \x20     targetRevision: main\n\
         \x20     path: .\n\
         \x20 destination:\n\
         \x20   cluster: in-cluster\n\
         \x20   namespace: {TARGET_NAMESPACE}\n\
         \x20 syncPolicy:\n\
         \x20   automated:\n\
         \x20     prune: false\n\
         \x20     selfHeal: true\n\
         \x20 requeueAfterSeconds: 15\n"
    );
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying the Application failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write(root: &Path, name: &str, contents: &str) {
    std::fs::write(root.join(name), contents)
        .unwrap_or_else(|error| panic!("write {name}: {error}"));
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

fn git_commit(cwd: &Path, message: &str) {
    git(
        cwd,
        &[
            "-c",
            "user.name=FerrisCD Test",
            "-c",
            "user.email=ferriscd@example.com",
            "commit",
            "-m",
            message,
        ],
    );
}

fn head_sha(cwd: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .output()
        .expect("git rev-parse must run");
    assert!(output.status.success(), "git rev-parse failed");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
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
        .expect("write manifest to kubectl stdin");
    child.wait_with_output().expect("kubectl must finish")
}

/// Runs `kubectl` and returns its trimmed stdout, or `None` on failure.
fn kubectl_jsonpath(args: &[&str]) -> Option<String> {
    let output = kubectl(args);
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}

fn status_jsonpath(template: &str) -> String {
    let output = kubectl(&[
        "get",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={template}"),
    ]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn health_status() -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        "jsonpath={.status.health.status}",
    ])
}

fn health_message() -> String {
    status_jsonpath("{.status.health.message}")
}

/// Health of the `Deployment` entry in `status.resources`.
fn deployment_resource_health() -> Option<String> {
    let key = format!("apps/Deployment/{TARGET_NAMESPACE}/{DEPLOYMENT_NAME}");
    let output = kubectl(&[
        "get",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={{.status.resources[?(@.key==\"{key}\")].health}}"),
    ]);
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}

/// Message of the `Deployment` entry in `status.resources`.
fn deployment_resource_message() -> String {
    let key = format!("apps/Deployment/{TARGET_NAMESPACE}/{DEPLOYMENT_NAME}");
    let output = kubectl(&[
        "get",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={{.status.resources[?(@.key==\"{key}\")].message}}"),
    ]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// `reason` of the (single) pod of the fixture `Deployment`.
fn pod_reason() -> String {
    let output = kubectl(&[
        "get",
        "pods",
        "-n",
        TARGET_NAMESPACE,
        "-l",
        "app=web",
        "-o",
        "jsonpath={.items[*].status.containerStatuses[*].state.waiting.reason}",
    ]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn synced_revision() -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        "jsonpath={.status.sync.revision}",
    ])
}

/// `metadata.generation` of the `Application`.
fn generation() -> Option<i64> {
    status_jsonpath("{.metadata.generation}").parse().ok()
}

/// `status.observedGeneration` of the `Application`.
fn observed_generation() -> Option<i64> {
    status_jsonpath("{.status.observedGeneration}").parse().ok()
}

fn application_ready() -> bool {
    status_jsonpath("{.status.conditions[?(@.type==\"Ready\")].status}") == "True"
}

/// Bumps `spec.requeueAfterSeconds` by one and returns the resulting `metadata.generation`.
///
/// `requeueAfterSeconds` is deliberately **not** part of `source_spec_hash`, so the bump forces a
/// full reconcile while the diff gate still decides to skip, and the new generation is the "this
/// pass started after my snapshot" signal.
fn bump_requeue_seconds_and_get_generation() -> i64 {
    let current: i64 = status_jsonpath("{.spec.requeueAfterSeconds}")
        .parse()
        .unwrap_or(15);
    let patch = format!(
        r#"{{"spec":{{"requeueAfterSeconds":{}}}}}"#,
        current.saturating_add(1)
    );
    let output = kubectl(&[
        "patch",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "--type=merge",
        "-p",
        &patch,
    ]);
    assert!(
        output.status.success(),
        "bumping spec.requeueAfterSeconds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    generation().expect("the Application must report metadata.generation")
}

/// Polls `condition` until it holds or `budget` elapses.
///
/// A bounded retry loop (never a fixed sleep on the assertion path) keeps the test deterministic on
/// a slow laptop while still failing loudly instead of hanging.
fn wait_for(budget: Duration, what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for {what}; status was: {}",
            status_jsonpath("{.status}")
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}
