//! Live `v1.3` end-to-end test for `T19.3`: the opt-in `ApplicationSet` controller generates a
//! fleet with a `matrix` generator on a real `kind` cluster, and deleting the `ApplicationSet`
//! preserves the generated `Application`s by default.
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. It asserts that `kubectl config
//! current-context` begins with `kind-` before doing anything, and it is `#[ignore]`d so `cargo
//! test` never runs it. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v1_3_applicationsets -- --ignored --test-threads=1
//! ```
//!
//! # What this pins
//!
//! 1. `Matrix(clusters × git.directories)` — the roadmap's hands-on experiment — produces exactly
//!    six `Application`s from **two** label-selected cluster registrations and **three** Git
//!    directories, all in the `ApplicationSet`'s own namespace (`T19.3` Trap Guard).
//! 2. Every generated `Application` carries the same-namespace `ownerReference` and the
//!    `ferriscd.io/applicationset` label, and the `ApplicationSet` reports `Ready=True` with
//!    `status.generatedCount: 6`.
//! 3. Deleting the `ApplicationSet` **keeps** the six `Application`s (the finalizer orphans them by
//!    dropping the owner reference) — the `preserveResourcesOnDeletion: true` default. Kubernetes
//!    garbage collection therefore has nothing to cascade to, which is what preserves the workloads
//!    those `Application`s own.
//!
//! Hermetic coverage of the same behaviour (generators, fan-out cap, prune and deletion planning,
//! conflict refusal) lives in `crates/ferriscd-engine/src/applicationset/` and
//! `crates/ferriscd-controller/src/applicationset_controller.rs`; this test proves the wiring to a
//! real API server, a real Git checkout, and the real cluster registry.
//!
//! Every wait is a bounded poll, never a fixed sleep, and the controller child process plus every
//! created object are cleaned up on every exit path (a `Drop` guard).

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and never
// ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Control-plane namespace: where the `ApplicationSet` lives and where it may generate.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// `AppProject` the generated `Application`s belong to.
const PROJECT: &str = "fleet";
/// The `ApplicationSet` under test.
const APPLICATIONSET: &str = "payments-fleet";
/// The two registered "clusters" the `clusters` generator selects (both labelled `env=prod`).
const CLUSTERS: [&str; 2] = ["eu-prod", "us-prod"];
/// The three Git directories the `git` generator discovers under `apps/*`.
const BASENAMES: [&str; 3] = ["api", "web", "worker"];
/// How many `Application`s the matrix must produce: `2 clusters × 3 directories`.
const EXPECTED: usize = 6;
/// `ferriscd.io/applicationset` label selector (`T19.3`).
const SELECTOR: &str = "ferriscd.io/applicationset=payments-fleet";
/// How long the controller may take to materialize the fleet.
const GENERATION_BUDGET: Duration = Duration::from_secs(240);
/// How long the orphan-on-delete may take after the `ApplicationSet` is deleted.
const DELETION_BUDGET: Duration = Duration::from_secs(180);
/// A self-signed CA that satisfies the registration `Secret`'s TLS material check (no connection is
/// ever made to the registered clusters: the `clusters` generator only reads the registry).
const CA_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIC9jCCAd6gAwIBAgIUBoS7jl1CY/lFamrFA9cf4+1SuiQwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZmVycmlzY2QtdGVzdC1jYTAeFw0yNjExMjUyMDM1NTVa
Fw0zNjExMjIyMDM1NTVaMBsxGTAXBgNVBAMMEGZlcnJpc2NkLXRlc3QtY2EwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDnhpGZMPGJjPp5bmH/n/06SxPn
c3SVSleCTLXImaOvNE9EKW+TqaNKP05MXrLKOWiLJ/29ypXFBODUA0rln/TkEEDi
/N0Wdl7LiWi4TeKFEcaiq8bwHsF2I7CMoMjMDqk9HOqUlfEPHBqejRonTBptbQQo
3ms+xcdjZMvZhhnu5NYVJz9jKQ8cImZDRtvG/5jIfy9wR5yobvVz8RisYm0mQA5G
P0Rq1A/BWZ3b8e9x+u+7QN/PEtOjKeYtO3mXfCad99DA0Uzy7LWVCY2La62+hWLk
KOK2vDJFWM8kKkg1ajyHoevJ5jzfpRG9f+9Zg1sOwyU1q4TRs54FR5poRgkBAgMB
AAGjMjAwMB0GA1UdDgQWBBS24qrqx3DwMC6fLIfaMrNGQ2gfRzAPBgNVHRMBAf8E
BTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCrjkfyoSSGNEHWt5rnFGGfw954odba
PkGYxW53EpZGpFQwNtb2AAc2tgFkjN+0HwjKW8rnZ6RVgdaLM+nJ0yLdEIzyEwfm
EBnhz4hDfDYBWNdLHStbIr/0E6cD73ST/wzD4lRMn0E0MSFAooESrat4QfPCUlxY
0+NBuRThvbqakP0LAGeSPrerxIthl6X3acaJrAcigOUoiHH13C5FuRGOOGkP8Zqk
VvvhRCE9YVNC/nP/0IrzmyUJjadxsSjY9K50kjOxukR8diF5fBhlpWz5n11sh+Sw
1LBIlI+iyFqhgHE6LNdbkoYW6AoNDCplqSopRJobnqv5RRL+JgwckPxy
-----END CERTIFICATE-----
"#;

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn matrix_generates_six_applications_and_deleting_the_applicationset_preserves_them() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    install_crds();
    ensure_control_plane_namespace();
    let _cleanup = ClusterCleanup;
    // A previous run may have left orphaned Applications behind — that is exactly the behaviour
    // this test proves, and their deletion can lag behind the run. Start from a clean fleet so no
    // assertion below can be satisfied by a leftover.
    remove_generated_applications();
    wait_for(DELETION_BUDGET, "the previous fleet to be gone", || {
        generated_names().is_empty()
    });
    let _controller = ControllerProcess::start();

    let fixture = tempfile::tempdir().expect("create the git fixture directory");
    let repository = fixture.path().join("fleet-config");
    write_fixture_repository(&repository);
    let repository = repository.to_str().expect("utf8 fixture path").to_owned();

    apply_project();
    for cluster in CLUSTERS {
        apply_cluster_registration(cluster);
    }
    apply_applicationset(&repository);

    // --- 1. the matrix materializes 2 clusters x 3 directories = 6 Applications -----------------
    wait_for(GENERATION_BUDGET, "six generated Applications", || {
        let fleet = generated_ownership();
        fleet.len() == EXPECTED
            && fleet
                .iter()
                .all(|(_, owner)| owner.as_deref() == Some(APPLICATIONSET))
    });
    let mut names: Vec<String> = generated_ownership()
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    names.sort();
    let mut expected: Vec<String> = Vec::with_capacity(EXPECTED);
    for basename in BASENAMES {
        for cluster in CLUSTERS {
            expected.push(format!("{basename}-{cluster}"));
        }
    }
    expected.sort();
    assert_eq!(names, expected, "Matrix(clusters x git.directories)");

    // Every generated Application lives in the ApplicationSet's own namespace: a cross-namespace
    // ownerReference is invalid in Kubernetes and a privilege-escalation path (Trap Guard).
    let namespaces = jsonpath(&[
        "-n",
        CONTROL_NAMESPACE,
        "get",
        "applications",
        "-l",
        SELECTOR,
        "-o",
        r#"jsonpath={range .items[*]}{.metadata.namespace}{"\n"}{end}"#,
    ]);
    for namespace in namespaces.lines().filter(|line| !line.is_empty()) {
        assert_eq!(
            namespace, CONTROL_NAMESPACE,
            "a generated Application must live in the ApplicationSet's namespace"
        );
    }

    // Same-namespace owner reference + the generated label on every Application.
    for (name, owner) in generated_ownership() {
        assert_eq!(
            owner.as_deref(),
            Some(APPLICATIONSET),
            "every generated Application is owned by the ApplicationSet (checked {name})"
        );
    }

    // The ApplicationSet reports its generation on /status.
    wait_for(GENERATION_BUDGET, "ApplicationSet Ready=True", || {
        jsonpath(&[
            "-n",
            CONTROL_NAMESPACE,
            "get",
            "applicationset",
            APPLICATIONSET,
            "-o",
            r#"jsonpath={.status.conditions[?(@.type=="Ready")].status}"#,
        ]) == "True"
    });
    assert_eq!(
        jsonpath(&[
            "-n",
            CONTROL_NAMESPACE,
            "get",
            "applicationset",
            APPLICATIONSET,
            "-o",
            "jsonpath={.status.generatedCount}",
        ]),
        EXPECTED.to_string(),
        "status.generatedCount must match the fleet"
    );

    // --- 2. deleting the ApplicationSet must NOT delete the fleet (the safe default) ------------
    kubectl(&[
        "-n",
        CONTROL_NAMESPACE,
        "delete",
        "applicationset",
        APPLICATIONSET,
        "--wait=false",
    ]);
    wait_for(DELETION_BUDGET, "the ApplicationSet to be gone", || {
        // The finalizer orphans the children and then releases the object.
        kubectl_try(&[
            "-n",
            CONTROL_NAMESPACE,
            "get",
            "applicationset",
            APPLICATIONSET,
            "-o",
            "name",
        ])
        .is_none()
    });

    let survivors = generated_names();
    assert_eq!(
        survivors.len(),
        EXPECTED,
        "preserveResourcesOnDeletion defaults to true: the generated Applications must survive, \
         got {survivors:?}"
    );

    // The surviving Applications are orphaned: no `ApplicationSet` owner reference remains, so
    // Kubernetes garbage collection has nothing to cascade to and the workloads they own stay.
    wait_for(
        DELETION_BUDGET,
        "the surviving Applications to be orphaned",
        || {
            let fleet = generated_ownership();
            !fleet.is_empty() && fleet.iter().all(|(_, owner)| owner.is_none())
        },
    );
}

// ---------------------------------------------------------------------------
// Cluster fixtures (kubectl)
// ---------------------------------------------------------------------------

/// Best-effort cleanup of everything this test creates, on every exit path.
struct ClusterCleanup;

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        remove_generated_applications();
        let _ = kubectl_try(&[
            "-n",
            CONTROL_NAMESPACE,
            "patch",
            "applicationset",
            APPLICATIONSET,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":null}}"#,
        ]);
        let _ = kubectl_try(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "applicationset",
            APPLICATIONSET,
            "--ignore-not-found",
            "--wait=false",
        ]);
        let _ = kubectl_try(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "appproject",
            PROJECT,
            "--ignore-not-found",
            "--wait=false",
        ]);
        for cluster in CLUSTERS {
            let _ = kubectl_try(&[
                "-n",
                CONTROL_NAMESPACE,
                "delete",
                "secret",
                cluster,
                "--ignore-not-found",
                "--wait=false",
            ]);
        }
    }
}

/// Removes every `Application`s this `ApplicationSet` generated.
///
/// The `Application` controller adds its own finalizer, and a generated `Application` targeting an
/// unreachable cluster never finishes its cleanup, so the finalizer has to be cleared first — one
/// object at a time, because `kubectl patch` takes no label selector.
fn remove_generated_applications() {
    for name in generated_names() {
        let _ = kubectl_try(&[
            "-n",
            CONTROL_NAMESPACE,
            "patch",
            "application",
            &name,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":null}}"#,
        ]);
        let _ = kubectl_try(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "application",
            &name,
            "--ignore-not-found",
            "--wait=false",
        ]);
    }
}

/// Runs `ferriscd controller --enable-applicationsets` as a child process, killed on drop.
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
                // The fixture repository is a local path, which the production URL policy rejects.
                "--allow-local-repos",
                // The whole point of the test: the opt-in `ApplicationSet` loop.
                "--enable-applicationsets",
                "--metrics-addr",
                "127.0.0.1:0",
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

fn current_kube_context() -> String {
    let output = kubectl(&["config", "current-context"]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn install_crds() {
    let directory = workspace_root().join("deploy/crds");
    for entry in std::fs::read_dir(&directory).expect("deploy/crds must exist") {
        let path = entry.expect("a CRD file").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            kubectl(&["apply", "-f", &path.to_string_lossy()]);
        }
    }
}

fn ensure_control_plane_namespace() {
    let manifest = format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {CONTROL_NAMESPACE}
"#
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

/// The project the fleet belongs to: it must permit the fixture repository and both clusters, so a
/// policy refusal cannot masquerade as a generation bug (`T12.1`).
fn apply_project() {
    let manifest = format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {PROJECT}
  namespace: {CONTROL_NAMESPACE}
spec:
  description: "T19.3 live ApplicationSet fleet"
  sourceRepos: ["*"]
  sourceNamespaces: ["{CONTROL_NAMESPACE}"]
  destinations:
    - cluster: "{}"
      namespace: "*"
    - cluster: "{}"
      namespace: "*"
  allowedServiceAccounts: []
"#,
        CLUSTERS[0], CLUSTERS[1]
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

/// A `ferriscd.io/secret-type=cluster` registration the `clusters` generator selects by `env=prod`.
fn apply_cluster_registration(cluster: &str) {
    let manifest = format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {cluster}
  namespace: {CONTROL_NAMESPACE}
  labels:
    ferriscd.io/secret-type: cluster
    env: prod
type: Opaque
stringData:
  server: https://{cluster}.example.com:6443
  bearerToken: not-a-real-token
  ca.crt: |
{}
"#,
        indent(CA_PEM.trim_end(), "    ")
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

fn apply_applicationset(repository: &str) {
    let manifest = format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: ApplicationSet
metadata:
  name: {APPLICATIONSET}
  namespace: {CONTROL_NAMESPACE}
spec:
  generators:
    - matrix:
        generators:
          - clusters:
              selector:
                matchLabels:
                  env: prod
          - git:
              repoURL: {repository}
              revision: HEAD
              directories:
                - path: apps/*
  template:
    metadata:
      name: "{{{{path.basename}}}}-{{{{cluster.name}}}}"
    spec:
      project: {PROJECT}
      source:
        git:
          repoURL: {repository}
          targetRevision: HEAD
          path: "{{{{path}}}}"
        renderer:
          plainYaml: {{}}
      destination:
        cluster: "{{{{cluster.name}}}}"
        namespace: "{{{{path.basename}}}}"
      requeueAfterSeconds: 600
"#
    );
    kubectl_with_stdin(&["apply", "-f", "-"], Some(&manifest));
}

/// Writes the fixture repository: one directory per service under `apps/`, each with a manifest, so
/// the `git` generator's `apps/*` glob discovers exactly `api`, `web`, and `worker`.
fn write_fixture_repository(repository: &Path) {
    std::fs::create_dir_all(repository).expect("create the fixture repository");
    for basename in BASENAMES {
        let directory = repository.join("apps").join(basename);
        std::fs::create_dir_all(&directory).expect("create a service directory");
        std::fs::write(
            directory.join("configmap.yaml"),
            format!(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {basename}-settings\ndata:\n  \
                 fleet: {APPLICATIONSET}\n"
            ),
        )
        .expect("write the service manifest");
    }
    git(repository, &["init", "--initial-branch=main"]);
    git(repository, &["add", "."]);
    git(
        repository,
        &[
            "-c",
            "user.name=FerrisCD Test",
            "-c",
            "user.email=test@ferriscd.io",
            "commit",
            "-m",
            "seed fleet directories",
        ],
    );
}

fn generated_names() -> Vec<String> {
    jsonpath(&[
        "-n",
        CONTROL_NAMESPACE,
        "get",
        "applications",
        "-l",
        SELECTOR,
        "-o",
        "name",
    ])
    .lines()
    .filter_map(|line| line.rsplit('/').next().map(str::to_owned))
    .collect()
}

/// Every generated `Application` with the name of its `ApplicationSet` owner (if any).
///
/// Rendered as `<name>=<owner>` by `jsonpath`; an orphaned object renders `<name>=`.
fn generated_ownership() -> Vec<(String, Option<String>)> {
    jsonpath(&[
        "-n",
        CONTROL_NAMESPACE,
        "get",
        "applications",
        "-l",
        SELECTOR,
        "-o",
        r#"jsonpath={range .items[*]}{.metadata.name}={.metadata.ownerReferences[0].name}{"\n"}{end}"#,
    ])
    .lines()
    .filter(|line| !line.is_empty())
    .map(|line| {
        let (name, owner) = line.split_once('=').unwrap_or((line, ""));
        (
            name.to_owned(),
            (!owner.is_empty()).then(|| owner.to_owned()),
        )
    })
    .collect()
}

fn indent(text: &str, prefix: &str) -> String {
    text.lines()
        .map(|line| format!("{prefix}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

/// Polls `predicate` until it holds or `budget` elapses, then fails with `label`.
fn wait_for(budget: Duration, label: &str, mut predicate: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() <= budget {
        if predicate() {
            return;
        }
        sleep(Duration::from_millis(250));
    }
    assert!(
        predicate(),
        "timed out after {budget:?} waiting for {label}"
    );
}

fn git(repository: &Path, args: &[&str]) {
    let output = Command::new("git")
        .current_dir(repository)
        .args(args)
        .output()
        .expect("git must be installed");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn jsonpath(args: &[&str]) -> String {
    let output = kubectl(args);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn kubectl(args: &[&str]) -> Output {
    let output = kubectl_with_stdin(args, None);
    assert!(
        output.status.success(),
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Runs `kubectl`, returning `None` when it fails (e.g. the object is gone).
fn kubectl_try(args: &[&str]) -> Option<String> {
    let output = kubectl_with_stdin(args, None);
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stdout.is_empty() || stdout.contains("No resources found") {
        // `jsonpath` over an empty list prints nothing; a plain `get` reports "not found" on stderr.
        if String::from_utf8_lossy(&output.stderr).contains("No resources found") {
            return None;
        }
    }
    Some(stdout)
}

fn kubectl_with_stdin(args: &[&str], stdin: Option<&str>) -> Output {
    let mut command = Command::new("kubectl");
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    let mut child = command.spawn().expect("kubectl must be installed");
    if let Some(manifest) = stdin {
        child
            .stdin
            .as_mut()
            .expect("a stdin pipe")
            .write_all(manifest.as_bytes())
            .expect("the manifest is written");
    }
    child.wait_with_output().expect("kubectl output")
}
