//! Live Phase 08 end-to-end test: ordered sync, CRD `Established` + discovery refresh,
//! immutable-field `Replace`, brownfield takeover, and ownership-verified pruning.
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. Every test starts by asserting that
//! `kubectl config current-context` begins with `kind-` (the same guard `make test-integration`
//! applies) and is marked `#[ignore]`, so `cargo test` never runs it accidentally. Invoke it with
//! `make test-integration` after `make kind-up`.
//!
//! # What this pins
//!
//! 1. **T08.3 (trap T6 / finding C3):** a brand-new `CustomResourceDefinition` and its custom
//!    resource in one commit succeed on the **first** sync: the CRD is applied, waited on until
//!    `Established`, discovery is refreshed, and the `Widget` is created in the same pass. The
//!    fixture is `examples/crd-and-cr/`, which is the documented example bundle.
//! 2. **T08.4 (trap T7, finding M3):** editing an `immutable: true` `ConfigMap` fails safely
//!    (the resource keeps its old data and the `Application` reports a terminal failure naming
//!    `ferriscd.io/sync-options: Replace=true`), and recreates cleanly once that annotation is
//!    committed.
//! 3. **T08.4 (trap T5, finding H6):** a `ConfigMap` created by `kubectl apply` is not adopted by
//!    default, and is adopted once `syncOptions.takeoverFieldManagers` lists
//!    `kubectl-client-side-apply`.
//! 4. **T08.5 (trap T10, findings C1/H3):** a resource removed from Git is pruned only when
//!    `prune: true` and only while its `ferriscd.io/tracking-id` is still ours; a
//!    `CustomResourceDefinition` orphan is preserved unless `syncOptions.pruneCRDs` opts in.
//!    The fixture proves **both** halves of the policy: the same orphans are first re-synced with
//!    `prune: false` (every one of them must be retained) and are only then re-synced with
//!    `prune: true`, after the cluster (not Git, whose annotation `stamp_ownership` overwrites)
//!    has made one of them genuinely foreign.
//!
//! Everything here is a bounded poll over `kubectl`, never a fixed `sleep`, so a slow laptop
//! still passes and a broken controller fails loudly.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and
// never ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Control-plane namespace the controller watches.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// `Application` name used by the CRD+CR test.
const APPLICATION_NAME: &str = "crd-and-cr";
/// Namespace the `Application` deploys into (`createNamespace: true` creates it).
const TARGET_NAMESPACE: &str = "ferriscd-crd-and-cr";

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn a_crd_and_its_custom_resource_sync_on_the_first_pass() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let _cluster_cleanup = ClusterCleanup::new();
    let _controller_cleanup = ControllerProcess::start();

    // The example bundle, committed verbatim: a CRD plus one of its custom resources.
    let fixture = tempfile::tempdir().expect("create git fixture directory");
    let repo = fixture.path();
    for entry in ["crd.yaml", "widget.yaml"] {
        let source = example_path(entry);
        let contents = std::fs::read_to_string(&source)
            .unwrap_or_else(|error| panic!("read {}: {error}", source.display()));
        write(repo, entry, &contents);
    }
    git_init(repo);
    apply_application(repo, "createNamespace: true\n      pruneCRDs: false");

    // The first reconcile must produce both objects: the CRD *and* the Widget. A controller that
    // re-queued the CR (the pre-T08.3 behaviour) would leave the Widget missing until a later
    // pass, so waiting for it here is the direct assertion of "first sync".
    wait_for(Duration::from_secs(300), "the Widget to exist", || {
        object_exists("widgets.example.com", "one", TARGET_NAMESPACE)
    });
    wait_for(
        Duration::from_secs(240),
        "status.inventory to track both",
        || {
            inventory_contains("apiextensions.k8s.io/CustomResourceDefinition//widgets.example.com")
                && inventory_contains(&format!("/Widget/{TARGET_NAMESPACE}/one"))
        },
    );
    wait_for(
        Duration::from_secs(240),
        "the Application to become Ready",
        || ready_condition_status().as_deref() == Some("True"),
    );
    assert_eq!(
        ready_condition_reason().as_deref(),
        Some("SyncSucceeded"),
        "a CRD + CR bundle must not stay PendingDependencies: {}",
        status_jsonpath("{.status}")
    );
}

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn an_immutable_configmap_fails_safely_and_recreates_with_replace() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let fixture = tempfile::tempdir().expect("create git fixture directory");
    let repo = fixture.path();
    let _cluster_cleanup = ClusterCleanup::new();
    let _controller_cleanup = ControllerProcess::start();

    write(
        repo,
        "namespace.yaml",
        &namespace_manifest(TARGET_NAMESPACE),
    );
    write(repo, "configmap.yaml", &immutable_configmap("a"));
    git_init(repo);
    apply_application(repo, "createNamespace: false\n      pruneCRDs: false");

    wait_for(Duration::from_secs(300), "the immutable ConfigMap", || {
        configmap_data(TARGET_NAMESPACE, "immutable") == Some("a".to_owned())
    });

    // Without the opt-in the edit must be refused: the data stays `a` and the Application reports
    // a terminal failure that names the opt-in.
    write(repo, "configmap.yaml", &immutable_configmap("b"));
    git_commit(repo, "edit an immutable ConfigMap");
    wait_for(
        Duration::from_secs(300),
        "the failure to name ferriscd.io/sync-options: Replace=true",
        || ready_condition_message().is_some_and(|message| message.contains("Replace=true")),
    );
    assert_eq!(
        configmap_data(TARGET_NAMESPACE, "immutable"),
        Some("a".to_owned()),
        "an immutable object must keep its data when the apply is refused"
    );

    // Opting in recreates it deterministically (delete -> wait for 404 -> apply, trap M3).
    write(
        repo,
        "configmap.yaml",
        &immutable_configmap_with_annotation("b", "ferriscd.io/sync-options: Replace=true"),
    );
    git_commit(repo, "opt into Replace for the immutable ConfigMap");
    wait_for(Duration::from_secs(300), "the recreated ConfigMap", || {
        configmap_data(TARGET_NAMESPACE, "immutable") == Some("b".to_owned())
    });
}

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn a_kubectl_applied_configmap_is_adopted_only_when_the_manager_is_listed() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let fixture = tempfile::tempdir().expect("create git fixture directory");
    let repo = fixture.path();
    let _cluster_cleanup = ClusterCleanup::new();
    let _controller_cleanup = ControllerProcess::start();

    write(
        repo,
        "namespace.yaml",
        &namespace_manifest(TARGET_NAMESPACE),
    );
    write(
        repo,
        "configmap.yaml",
        &plain_configmap("brownfield", "from-git"),
    );
    git_init(repo);

    // Brownfield: the object exists first, owned by `kubectl-client-side-apply`.
    ensure_namespace(TARGET_NAMESPACE);
    kubectl_stdin(
        &["apply", "-f", "-"],
        &plain_configmap("brownfield", "from-kubectl"),
    );
    apply_application(repo, "createNamespace: false\n      pruneCRDs: false");

    // Without `takeoverFieldManagers` the apply must fail and name the conflicting manager.
    wait_for(
        Duration::from_secs(300),
        "a field-manager conflict naming kubectl-client-side-apply",
        || {
            ready_condition_message().is_some_and(|message| {
                message.contains("kubectl-client-side-apply")
                    && message.contains("takeoverFieldManagers")
            })
        },
    );
    assert_eq!(
        configmap_data(TARGET_NAMESPACE, "brownfield"),
        Some("from-kubectl".to_owned()),
        "a foreign field manager must never be forced silently (trap T5)"
    );

    // Listing the manager opts into one forced retry of that single resource.
    patch_application_spec(
        r#"{"spec":{"syncPolicy":{"syncOptions":{"takeoverFieldManagers":["kubectl-client-side-apply"]}}}}"#,
    );
    wait_for(
        Duration::from_secs(300),
        "the takeover to apply Git's value",
        || configmap_data(TARGET_NAMESPACE, "brownfield") == Some("from-git".to_owned()),
    );
}

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn pruning_is_ownership_verified_and_protects_crd_orphans() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    let fixture = tempfile::tempdir().expect("create git fixture directory");
    let repo = fixture.path();
    let _cluster_cleanup = ClusterCleanup::new();
    let _controller_cleanup = ControllerProcess::start();

    write(
        repo,
        "namespace.yaml",
        &namespace_manifest(TARGET_NAMESPACE),
    );
    write(repo, "kept.yaml", &plain_configmap("kept", "value"));
    write(repo, "removed.yaml", &plain_configmap("removed", "value"));
    // `optout` carries `ferriscd.io/prune: "false"`, so the live object carries it too (SSA keeps
    // the annotation): once it leaves Git it is an orphan FerrisCD must retain.
    write(
        repo,
        "optout.yaml",
        &plain_configmap_with_annotation("optout", "value", "ferriscd.io/prune: \"false\""),
    );
    // `foreign` is *ours* in Git on purpose: the apply stamps our `tracking-id` onto it, so a
    // foreign-ownership test needs the cluster edited below, never a Git annotation (which the
    // stamp would overwrite).
    write(repo, "foreign.yaml", &plain_configmap("foreign", "value"));
    write(repo, "crd.yaml", &widget_crd());
    git_init(repo);
    apply_application(repo, "createNamespace: false\n      pruneCRDs: false");

    // Pass 1, `prune: false`: every object is created *and stamped with our tracking-id*, which is
    // what makes the retention and prune assertions below about the rails and not about a missing
    // marker.
    wait_for(Duration::from_secs(300), "the four ConfigMaps", || {
        ["kept", "removed", "optout", "foreign"]
            .iter()
            .all(|name| configmap_data(TARGET_NAMESPACE, name).is_some())
    });
    wait_for(
        Duration::from_secs(240),
        "the inventory to track every fixture object",
        || {
            ["kept", "removed", "optout", "foreign"]
                .iter()
                .all(|name| inventory_contains(&format!("/ConfigMap/{TARGET_NAMESPACE}/{name}")))
                && inventory_contains(&format!("/Namespace//{TARGET_NAMESPACE}"))
                && inventory_contains(
                    "apiextensions.k8s.io/CustomResourceDefinition//widgets.example.com",
                )
        },
    );

    // --- the `prune: false` half of the rail ------------------------------------------------
    // Three ConfigMaps and the CRD leave Git while pruning is still off. Nothing may be deleted:
    // this is the case a `prune: true` pass never exercises.
    for name in ["removed.yaml", "foreign.yaml", "optout.yaml", "crd.yaml"] {
        std::fs::remove_file(repo.join(name))
            .unwrap_or_else(|error| panic!("remove {name}: {error}"));
    }
    git_commit(repo, "remove three ConfigMaps and the CRD from Git");
    let head = git_head(repo);
    wait_for(
        Duration::from_secs(300),
        "the retention pass to observe the new revision",
        || status_jsonpath("{.status.sync.revision}") == head,
    );
    wait_for(
        Duration::from_secs(240),
        "the retained orphans to be reported",
        || ready_condition_message().is_some_and(|message| message.contains("orphan(s) retained")),
    );
    for name in ["removed", "foreign", "optout"] {
        assert!(
            configmap_data(TARGET_NAMESPACE, name).is_some(),
            "{name} must be retained while automated.prune is false"
        );
    }
    assert!(
        object_exists(
            "customresourcedefinitions.apiextensions.k8s.io",
            "widgets.example.com",
            ""
        ),
        "a CRD orphan must be retained while automated.prune is false"
    );

    // --- make `foreign` genuinely another Application's object -------------------------------
    // Now (and only now) the marker is replaced: a Git annotation would have been overwritten by
    // `stamp_ownership`, so the takeover has to happen on the live object.
    set_tracking_id(
        TARGET_NAMESPACE,
        "foreign",
        "ferriscd-system/another-app:/ConfigMap:default/foreign",
    );

    // --- enable pruning: exactly one orphan may be deleted -----------------------------------
    enable_prune();
    wait_for(
        Duration::from_secs(600),
        "the owned orphan to be pruned",
        || configmap_data(TARGET_NAMESPACE, "removed").is_none(),
    );
    wait_for(
        Duration::from_secs(240),
        "the pruned ConfigMap to leave the inventory",
        || !inventory_contains(&format!("/ConfigMap/{TARGET_NAMESPACE}/removed")),
    );

    assert!(
        configmap_data(TARGET_NAMESPACE, "kept").is_some(),
        "a resource still in Git must never be pruned"
    );
    assert_eq!(
        configmap_data(TARGET_NAMESPACE, "optout"),
        Some("value".to_owned()),
        "ferriscd.io/prune=false must keep the orphan"
    );
    assert!(
        configmap_data(TARGET_NAMESPACE, "foreign").is_some(),
        "an object whose tracking-id belongs to another Application must never be pruned"
    );
    assert!(
        object_exists(
            "customresourcedefinitions.apiextensions.k8s.io",
            "widgets.example.com",
            ""
        ),
        "a CustomResourceDefinition orphan must be preserved unless pruneCRDs opts in"
    );
    let retained = status_jsonpath("{.status.conditions[?(@.type==\"Ready\")].message}");
    assert!(
        retained.contains("orphan(s) retained"),
        "retained orphans must be visible in /status: {retained}"
    );
}

// ---------------------------------------------------------------------
// Cluster helpers
// ---------------------------------------------------------------------

/// Deletes everything these tests create.
struct ClusterCleanup;

impl ClusterCleanup {
    fn new() -> Self {
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
        let _ = kubectl(&[
            "delete",
            "crd",
            "widgets.example.com",
            "--ignore-not-found=true",
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
        let _ = kubectl(&[
            "delete",
            "crd",
            "widgets.example.com",
            "--ignore-not-found=true",
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
                // The fixture repository is a local path, which the production URL policy rejects.
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

// ---------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------

/// Absolute path of a committed example, independent of the test target's package directory.
fn example_path(name: &str) -> PathBuf {
    // `CARGO_MANIFEST_DIR` is `crates/ferriscd-cli` (this file is `#[path]`-included from that
    // package's `tests/`), and `../..` is the workspace root where `examples/` lives.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/crd-and-cr")
        .join(name)
}

fn write(root: &Path, name: &str, contents: &str) {
    std::fs::write(root.join(name), contents)
        .unwrap_or_else(|error| panic!("write {name}: {error}"));
}

fn git_init(cwd: &Path) {
    git(cwd, &["init", "--initial-branch=main"]);
    git(cwd, &["add", "--all"]);
    git_commit(cwd, "seed manifests");
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
    git(cwd, &["add", "--all"]);
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

/// The full SHA `HEAD` points at, which is what `status.sync.revision` records.
fn git_head(cwd: &Path) -> String {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(cwd)
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git rev-parse HEAD failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn namespace_manifest(namespace: &str) -> String {
    format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n")
}

fn plain_configmap(name: &str, value: &str) -> String {
    format!("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {name}\ndata:\n  key: {value}\n")
}

fn plain_configmap_with_annotation(name: &str, value: &str, annotation: &str) -> String {
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {name}\n  annotations:\n    \
         {annotation}\ndata:\n  key: {value}\n"
    )
}

/// A `ConfigMap` the API server refuses to mutate once created.
fn immutable_configmap(value: &str) -> String {
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: immutable\nimmutable: true\n\
         data:\n  key: {value}\n"
    )
}

fn immutable_configmap_with_annotation(value: &str, annotation: &str) -> String {
    format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: immutable\n  annotations:\n    \
         {annotation}\nimmutable: true\ndata:\n  key: {value}\n"
    )
}

/// The CRD half of `examples/crd-and-cr/`, inlined so the pruning test can remove it from Git.
fn widget_crd() -> String {
    std::fs::read_to_string(example_path("crd.yaml")).expect("read the example CRD")
}

// ---------------------------------------------------------------------
// kubectl helpers
// ---------------------------------------------------------------------

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

fn kubectl_stdin(args: &[&str], stdin: &str) -> Output {
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

/// Installs the committed `Application` CRD (idempotent).
fn install_crds() {
    let crds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crds");
    let output = kubectl(&["apply", "-f", &crds.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/crds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the shipped `default` `AppProject` (`T12.1`).
///
/// Every `Application` is validated against the project it references and a missing project is a
/// terminal denial, so the live suite has to install the same manifest an operator applies.
/// Idempotent, and it must run *after* the control-plane namespace exists.
fn ensure_default_project() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/manifests/default-project.yaml");
    let output = kubectl(&["apply", "-f", &manifest.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/manifests/default-project.yaml failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn ensure_namespace(namespace: &str) {
    let output = kubectl_stdin(&["apply", "-f", "-"], &namespace_manifest(namespace));
    assert!(
        output.status.success(),
        "creating namespace {namespace} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the `Application` that points at the fixture repository.
///
/// `sync_options` is inserted verbatim under `syncOptions`, so each test states the policy it
/// exercises (`createNamespace`, `pruneCRDs`, …).
fn apply_application(repo: &Path, sync_options: &str) {
    let manifest = format!(
        "apiVersion: ferriscd.io/v1alpha1\n\
         kind: Application\n\
         metadata:\n\
         \x20 name: {APPLICATION_NAME}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         spec:\n\
         \x20 source:\n\
         \x20   git:\n\
         \x20     repoURL: {}\n\
         \x20     targetRevision: main\n\
         \x20     path: .\n\
         \x20 destination:\n\
         \x20   cluster: in-cluster\n\
         \x20   namespace: {TARGET_NAMESPACE}\n\
         \x20 syncPolicy:\n\
         \x20   automated:\n\
         \x20     prune: false\n\
         \x20     selfHeal: true\n\
         \x20   syncOptions:\n\
         \x20     {sync_options}\n\
         \x20 requeueAfterSeconds: 15\n",
        repo.display()
    );
    let output = kubectl_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying the Application failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Merge-patches the `Application` (used to flip one policy field at a time).
fn patch_application_spec(patch: &str) {
    let output = kubectl(&[
        "patch",
        "application",
        APPLICATION_NAME,
        "-n",
        CONTROL_NAMESPACE,
        "--type=merge",
        "-p",
        patch,
    ]);
    assert!(
        output.status.success(),
        "patching the Application failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Enables `automated.prune` on the running `Application`.
fn enable_prune() {
    patch_application_spec(
        r#"{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}"#,
    );
}

/// Overwrites the live `ferriscd.io/tracking-id` of a fixture `ConfigMap`.
///
/// The only way to make an object FerrisCD applied genuinely *foreign*: a Git-side annotation is
/// overwritten by `stamp_ownership` on every apply, so the takeover has to happen on the cluster.
fn set_tracking_id(namespace: &str, name: &str, tracking_id: &str) {
    let annotation = format!("ferriscd.io/tracking-id={tracking_id}");
    let output = kubectl(&[
        "annotate",
        "configmap",
        name,
        "-n",
        namespace,
        "--overwrite",
        &annotation,
    ]);
    assert!(
        output.status.success(),
        "annotating {name} with {annotation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

fn ready_condition_status() -> Option<String> {
    non_empty(status_jsonpath(
        "{.status.conditions[?(@.type==\"Ready\")].status}",
    ))
}

fn ready_condition_reason() -> Option<String> {
    non_empty(status_jsonpath(
        "{.status.conditions[?(@.type==\"Ready\")].reason}",
    ))
}

fn ready_condition_message() -> Option<String> {
    non_empty(status_jsonpath(
        "{.status.conditions[?(@.type==\"Ready\")].message}",
    ))
}

fn inventory_contains(key: &str) -> bool {
    status_jsonpath("{.status.inventory[*].key}")
        .split_whitespace()
        .any(|entry| entry == key)
}

/// Reads `.data.key` of a fixture `ConfigMap`.
fn configmap_data(namespace: &str, name: &str) -> Option<String> {
    non_empty(
        kubectl_jsonpath(&[
            "get",
            "configmap",
            name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.data.key}",
        ])
        .unwrap_or_default(),
    )
}

/// Returns whether `kind/name` (optionally namespaced) exists.
fn object_exists(kind: &str, name: &str, namespace: &str) -> bool {
    let mut args = vec!["get", kind, name, "-o", "name"];
    if !namespace.is_empty() {
        args.push("-n");
        args.push(namespace);
    }
    kubectl(&args).status.success()
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Runs `kubectl` and returns its trimmed stdout, or `None` on failure.
fn kubectl_jsonpath(args: &[&str]) -> Option<String> {
    let output = kubectl(args);
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Polls `condition` until it holds or `budget` elapses.
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
