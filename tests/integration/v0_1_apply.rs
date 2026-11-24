//! Live `v0.1` end-to-end test: `ferriscd apply` against a local Git repository on
//! a real `kind` cluster.
//!
//! # Safety gate
//!
//! This test **must never touch a non-`kind` cluster**. The very first thing it does
//! is assert that `kubectl config current-context` starts with `kind-`, mirroring the
//! `test-integration` Makefile guard. It is marked `#[ignore]` so `cargo test` never
//! runs it accidentally; invoke it explicitly with `make test-integration`.

// Test-only shell-out helpers are allowed to panic: this entire file is compiled as a
// test target and never ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const TEST_NAMESPACE: &str = "ferriscd-demo";
const DEPLOYMENT_NAME: &str = "demo-app";
const SERVICE_NAME: &str = "demo-app";
const CLUSTER_ROLE_NAME: &str = "ferriscd-demo-reader";

/// Creates a local Git repository containing `examples/basic/*` plus a cluster-scoped
/// `ClusterRole`, applies it twice with `ferriscd apply`, and verifies both the applied
/// objects and their real Discovery-derived scope against `kubectl`.
#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn apply_examples_basic_from_local_git_repo_is_idempotent_and_scoped_correctly() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    // Best-effort cleanup even if an assertion below panics.
    let _cleanup = ResourceCleanup;

    let fixture = tempfile::tempdir().expect("create git fixture directory");
    let repo = fixture.path();
    write_fixture(repo);
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git(
        repo,
        &[
            "-c",
            "user.name=FerrisCD Test",
            "-c",
            "user.email=ferriscd@example.com",
            "commit",
            "-m",
            "seed manifests",
        ],
    );

    let repo = repo.to_str().expect("utf8 fixture path");
    let args = [
        "apply",
        "--repo",
        repo,
        "--rev",
        "main",
        "--path",
        ".",
        "--namespace",
        TEST_NAMESPACE,
    ];

    let first = ferriscd(&args);
    assert_success("first apply", &first);
    let second = ferriscd(&args);
    assert_success("second apply (idempotent SSA no-op)", &second);

    assert_resources_ready();
}

/// Deletes the test namespace and cluster-scoped object.
struct ResourceCleanup;

impl Drop for ResourceCleanup {
    fn drop(&mut self) {
        let _ = Command::new("kubectl")
            .args([
                "delete",
                "namespace",
                TEST_NAMESPACE,
                "--ignore-not-found=true",
                "--wait=false",
            ])
            .output();
        let _ = Command::new("kubectl")
            .args([
                "delete",
                "clusterrole",
                CLUSTER_ROLE_NAME,
                "--ignore-not-found=true",
            ])
            .output();
    }
}

/// Runs `kubectl config current-context`, returning the trimmed context name.
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

/// Copies the checked-in `examples/basic` manifests and adds a cluster-scoped object.
fn write_fixture(repo: &Path) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/basic");
    let dest = repo.join("examples/basic");
    std::fs::create_dir_all(&dest).expect("create examples/basic fixture dir");
    for name in [
        "namespace.yaml",
        "deployment.yaml",
        "service.yaml",
        "configmap.yaml",
    ] {
        std::fs::copy(src.join(name), dest.join(name))
            .unwrap_or_else(|err| panic!("copy {name} from {}: {err}", src.join(name).display()));
    }

    let name_line = format!("  name: {CLUSTER_ROLE_NAME}");
    let cluster_role = [
        "apiVersion: rbac.authorization.k8s.io/v1",
        "kind: ClusterRole",
        "metadata:",
        name_line.as_str(),
        "rules:",
        "  - apiGroups: [\"\"]",
        "    resources: [\"configmaps\"]",
        "    verbs: [\"get\", \"list\"]",
        "",
    ]
    .join("\n");
    std::fs::write(repo.join("clusterrole.yaml"), cluster_role).expect("write clusterrole fixture");
}

/// Runs `git` in `cwd` and asserts it succeeds.
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

/// Runs the compiled `ferriscd` binary, returning its raw output.
fn ferriscd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferriscd"))
        .args(args)
        .output()
        .expect("ferriscd binary must run")
}

fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Polls `kubectl` with a bounded retry loop (not a single sleep) until the Namespace,
/// Service, ready Deployment, and cluster-scoped ClusterRole are all observed.
fn assert_resources_ready() {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        if namespace_exists() && service_exists() && deployment_ready() && cluster_role_ready() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for applied resources to become ready"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn kubectl(args: &[&str]) -> Output {
    Command::new("kubectl")
        .args(args)
        .output()
        .expect("kubectl must run")
}

fn resource_exists(args: &[&str]) -> bool {
    kubectl(args).status.success()
}

fn namespace_exists() -> bool {
    resource_exists(&["get", "namespace", TEST_NAMESPACE, "-o", "name"])
}

fn service_exists() -> bool {
    resource_exists(&[
        "get",
        "service",
        SERVICE_NAME,
        "-n",
        TEST_NAMESPACE,
        "-o",
        "name",
    ])
}

fn deployment_ready() -> bool {
    let output = kubectl(&[
        "get",
        "deployment",
        DEPLOYMENT_NAME,
        "-n",
        TEST_NAMESPACE,
        "-o",
        "jsonpath={.status.readyReplicas}",
    ]);
    output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "1"
}

/// The `ClusterRole` must exist *and* have no namespace, proving real Discovery scope
/// handling for cluster-scoped objects.
fn cluster_role_ready() -> bool {
    let name = kubectl(&[
        "get",
        "clusterrole",
        CLUSTER_ROLE_NAME,
        "-o",
        "jsonpath={.metadata.name}",
    ]);
    if !name.status.success() || String::from_utf8_lossy(&name.stdout).trim() != CLUSTER_ROLE_NAME {
        return false;
    }

    let namespace = kubectl(&[
        "get",
        "clusterrole",
        CLUSTER_ROLE_NAME,
        "-o",
        "jsonpath={.metadata.namespace}",
    ]);
    namespace.status.success() && String::from_utf8_lossy(&namespace.stdout).trim().is_empty()
}
