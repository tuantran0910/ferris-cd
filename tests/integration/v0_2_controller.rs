//! Live `v0.2` end-to-end test: the real controller (`ferriscd controller`) reconciles an
//! `Application` from a local Git repository on a real `kind` cluster.
//!
//! # Safety gate
//!
//! This test **must never touch a non-`kind` cluster**. The very first thing it does is assert
//! that `kubectl config current-context` starts with `kind-`, mirroring the
//! `test-integration` Makefile guard. It is marked `#[ignore]` so `cargo test` never runs it
//! accidentally; invoke it explicitly with `make test-integration`.
//!
//! # What this pins
//!
//! 1. An `Application` CR pointing at a local Git repository is reconciled end to end:
//!    `status.sync.revision` and `status.inventory` are populated and the workloads exist.
//! 2. A new Git commit is picked up automatically (`status.sync.revision` advances without
//!    anyone touching the `Application`).
//! 3. Removing a ConfigMap from Git does **not** lose it: the object stays live with its
//!    `ferriscd.io/tracking-id` and stays in `status.inventory`. That is the observable half
//!    of trap T1 — the controller still reads the removed resource from `status.inventory`.
//! 4. Enabling `automated.prune` afterwards deletes **only** that removed ConfigMap. This is
//!    the end-to-end proof of the union fetch + ownership classification (T06.3): the object
//!    is no longer in Git at all, so the controller can only have learned about it from
//!    `status.inventory` and can only have deleted it after classifying the live object
//!    `OwnedBySelf` from its `tracking-id`. Every other resource must survive.
//! 5. **T07.5:** a second reconcile of the already-synced `Application` issues **zero** mutating
//!    `Patch` calls. `metadata.resourceVersion` of the managed objects is the observable: an
//!    apply always bumps it, while a `dryRun=All` diff does not persist anything. A control leg
//!    hand-edits the ConfigMap and waits for self-heal, proving the same observation *does*
//!    detect a write (otherwise "version unchanged" would be vacuous).
//!
//! Hermetic coverage of the same classification (no cluster) lives in
//! `crates/ferriscd-controller/src/live_state.rs`; the hermetic proof that an already-synced
//! `Application` performs zero mutating applies (counted at the `Applier` seam) lives in
//! `crates/ferriscd-controller/src/sync.rs`.
//!
//! # Prerequisites (manual)
//!
//! ```text
//! make kind-up
//! kubectl apply -f deploy/crds
//! ```
//!
//! The test installs the CRDs itself if they are missing, creates the control-plane namespace,
//! and starts/stops the controller binary as a child process.

// Test-only shell-out helpers are allowed to panic: this entire file is compiled as a test
// target and never ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Control-plane namespace the controller watches.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Namespace the `Application` deploys into (created by a manifest in the fixture repo).
const TARGET_NAMESPACE: &str = "ferriscd-v0-2-deployment";
/// `Application` name.
const APPLICATION_NAME: &str = "payments";
/// ConfigMaps the fixture repo declares initially.
const KEPT_CONFIGMAP: &str = "settings";
const REMOVED_CONFIGMAP: &str = "removed-later";

/// Expected `tracking-id` of the removed ConfigMap.
fn removed_tracking_id() -> String {
    format!(
        "{CONTROL_NAMESPACE}/{APPLICATION_NAME}:/ConfigMap:{TARGET_NAMESPACE}/{REMOVED_CONFIGMAP}"
    )
}

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn controller_reconciles_an_application_and_keeps_the_inventory_of_a_removed_resource() {
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
    let first = write_fixture_and_commit(repo);
    apply_application(repo.to_str().expect("utf8 fixture path"));

    // The first reconcile may need one requeue cycle: the Namespace manifest is applied while
    // the ConfigMaps are deferred (`DeferredPendingNamespace`) until it exists.
    wait_for(Duration::from_secs(240), "both ConfigMaps applied", || {
        configmap_exists(KEPT_CONFIGMAP) && configmap_exists(REMOVED_CONFIGMAP)
    });
    wait_for(
        Duration::from_secs(240),
        "status.inventory populated",
        || {
            inventory_contains(&gknn(KEPT_CONFIGMAP))
                && inventory_contains(&gknn(REMOVED_CONFIGMAP))
        },
    );
    wait_for(Duration::from_secs(240), "first revision synced", || {
        synced_revision().as_deref() == Some(first.as_str())
    });

    // A new commit is reconciled without anyone touching the Application.
    let second = commit_without_removed_configmap(repo);
    wait_for(Duration::from_secs(600), "second revision synced", || {
        synced_revision().as_deref() == Some(second.as_str())
    });

    // Trap T1: the resource deleted from Git is still known, still tracked and still live.
    assert!(
        inventory_contains(&gknn(REMOVED_CONFIGMAP)),
        "status.inventory must still contain the ConfigMap removed from Git, got: {}",
        status_jsonpath("{.status.inventory[*].key}")
    );
    assert!(
        configmap_exists(REMOVED_CONFIGMAP),
        "the removed ConfigMap must not vanish (prune is disabled in this fixture)"
    );
    assert_eq!(
        configmap_tracking_id(REMOVED_CONFIGMAP).as_deref(),
        Some(removed_tracking_id().as_str()),
        "the removed ConfigMap must keep its ownership marker"
    );
    assert!(
        application_ready(),
        "the Application must report Ready=True, got: {}",
        status_jsonpath("{.status.conditions}")
    );
    assert_eq!(
        status_jsonpath("{.status.sync.status}"),
        "Synced",
        "a removed-but-tracked resource must not keep the sync out of the Synced state"
    );

    // T06.3 end to end: the removed ConfigMap is *only* reachable through `status.inventory`.
    // Enabling prune must delete it (which requires the reader to have fetched it and
    // classified the live object `OwnedBySelf`), and must leave every desired object alone.
    enable_prune();
    wait_for(
        Duration::from_secs(600),
        "the removed ConfigMap to be pruned",
        || !configmap_exists(REMOVED_CONFIGMAP),
    );
    wait_for(
        Duration::from_secs(240),
        "the pruned ConfigMap to leave status.inventory",
        || !inventory_contains(&gknn(REMOVED_CONFIGMAP)),
    );
    assert!(
        configmap_exists(KEPT_CONFIGMAP),
        "a resource that is still in Git must never be pruned"
    );
    assert!(
        inventory_contains(&gknn(KEPT_CONFIGMAP)),
        "the desired ConfigMap must stay tracked, got: {}",
        status_jsonpath("{.status.inventory[*].key}")
    );
    assert!(
        application_ready(),
        "the Application must stay Ready=True after a prune, got: {}",
        status_jsonpath("{.status.conditions}")
    );

    // ---------------------------------------------------------------------
    // T07.5: an already-synced Application performs zero mutating Patch calls
    // ---------------------------------------------------------------------
    // `resourceVersion` is bumped by every persisted write and is *not* touched by a
    // `dryRun=All` PATCH, so an unchanged pair of versions across a completed reconcile is the
    // live proof that the diff gate issued no mutating apply.
    let versions_before =
        managed_resource_versions().expect("the managed objects must report a resourceVersion");

    // Force a full pass that is guaranteed to start after this point: bumping
    // `spec.requeueAfterSeconds` raises `metadata.generation`, and `status.observedGeneration`
    // only reaches that value once a reconcile that observed it has finished its apply phase.
    // It is not part of `source_spec_hash`, so the gate must skip (nothing drifted).
    let generation = bump_requeue_seconds_and_get_generation();
    wait_for(
        Duration::from_secs(240),
        "the diff gate to skip the already-synced Application",
        || {
            observed_generation() == Some(generation)
                && ready_reason().as_deref() == Some(REASON_SYNC_SKIPPED)
        },
    );
    assert_eq!(
        managed_resource_versions().as_ref(),
        Some(&versions_before),
        "an already-synced Application must perform zero mutating Patch calls (resourceVersion \
         moved, so something was written)"
    );
    assert_eq!(
        status_jsonpath("{.status.sync.status}"),
        "Synced",
        "a skipped, already-synced pass must still report Synced"
    );

    // Control: the same observation must detect a write, otherwise "unchanged" proves nothing.
    assert!(configmap_exists(KEPT_CONFIGMAP));
    assert_eq!(
        configmap_data_key(KEPT_CONFIGMAP).as_deref(),
        Some("value"),
        "the fixture ConfigMap starts with the value from Git"
    );
    patch_configmap_data_key(KEPT_CONFIGMAP, "drifted");
    wait_for(
        Duration::from_secs(600),
        "self-heal to restore the drifted ConfigMap",
        || configmap_data_key(KEPT_CONFIGMAP).as_deref() == Some("value"),
    );
    assert_ne!(
        managed_resource_versions().as_ref(),
        Some(&versions_before),
        "healing drift must bump resourceVersion, which is what the zero-write assertion detects"
    );
}

/// Condition reason the diff gate reports when it deliberately applied nothing.
const REASON_SYNC_SKIPPED: &str = "SyncSkipped";

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

/// Writes the fixture repository (Namespace + two ConfigMaps) and commits it.
fn write_fixture_and_commit(repo: &Path) -> String {
    write(
        repo,
        "namespace.yaml",
        &format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {TARGET_NAMESPACE}\n"),
    );
    write(
        repo,
        "configmap-settings.yaml",
        &format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {KEPT_CONFIGMAP}\ndata:\n  key: value\n"
        ),
    );
    write(
        repo,
        "configmap-removed.yaml",
        &format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {REMOVED_CONFIGMAP}\ndata:\n  key: value\n"
        ),
    );

    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git_commit(repo, "seed manifests");
    head_sha(repo)
}

/// Deletes the second ConfigMap and commits the removal.
fn commit_without_removed_configmap(repo: &Path) -> String {
    std::fs::remove_file(repo.join("configmap-removed.yaml"))
        .expect("remove the second ConfigMap manifest");
    git(repo, &["add", "--all"]);
    git_commit(repo, "remove the second configmap");
    head_sha(repo)
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

/// Installs the committed CRDs (idempotent).
fn install_crds() {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package, not this file's
    // directory: this file is `#[path]`-included from
    // `crates/ferriscd-cli/tests/v0_2_controller.rs` (the workspace root is a virtual manifest
    // and has no test targets of its own), so the manifest dir is `crates/ferriscd-cli` and
    // `../..` is the workspace root where `deploy/` lives.
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
/// `automated: { selfHeal: true }` is required since T07.5: the diff gate refuses to apply
/// anything for `automated: None` (manual-only) and, with `selfHeal: false`, only on a source
/// change. Pruning stays off so the "removed from Git is kept" leg remains observable.
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

/// Enables `automated.prune` on the running `Application`.
///
/// A merge patch keeps the rest of the spec intact; the controller picks the change up through
/// its watch, so the very next reconcile has pruning on.
fn enable_prune() {
    let patch = r#"{"spec":{"syncPolicy":{"automated":{"prune":true,"selfHeal":true}}}}"#;
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
        "enabling automated.prune failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Canonical GKNN key of a ConfigMap in the target namespace.
fn gknn(name: &str) -> String {
    format!("/ConfigMap/{TARGET_NAMESPACE}/{name}")
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

fn configmap_exists(name: &str) -> bool {
    kubectl(&[
        "get",
        "configmap",
        name,
        "-n",
        TARGET_NAMESPACE,
        "-o",
        "name",
    ])
    .status
    .success()
}

fn configmap_tracking_id(name: &str) -> Option<String> {
    let output = kubectl(&[
        "get",
        "configmap",
        name,
        "-n",
        TARGET_NAMESPACE,
        "-o",
        "jsonpath={.metadata.annotations.ferriscd\\.io/tracking-id}",
    ]);
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

fn inventory_contains(key: &str) -> bool {
    status_jsonpath("{.status.inventory[*].key}")
        .split_whitespace()
        .any(|entry| entry == key)
}

/// `(resourceVersion of the target Namespace, resourceVersion of the kept ConfigMap)`.
///
/// Both objects are managed by the `Application`, so any mutating apply during a reconcile
/// bumps one of them. A `dryRun=All` PATCH never persists, so it cannot move these values.
fn managed_resource_versions() -> Option<(String, String)> {
    let namespace = kubectl_jsonpath(&[
        "get",
        "namespace",
        TARGET_NAMESPACE,
        "-o",
        "jsonpath={.metadata.resourceVersion}",
    ])?;
    let configmap = kubectl_jsonpath(&[
        "get",
        "configmap",
        KEPT_CONFIGMAP,
        "-n",
        TARGET_NAMESPACE,
        "-o",
        "jsonpath={.metadata.resourceVersion}",
    ])?;
    Some((namespace, configmap))
}

/// `metadata.generation` of the `Application`.
fn generation() -> Option<i64> {
    status_jsonpath("{.metadata.generation}").parse().ok()
}

/// `status.observedGeneration` of the `Application`.
fn observed_generation() -> Option<i64> {
    status_jsonpath("{.status.observedGeneration}").parse().ok()
}

/// Reason of the `Ready` condition.
fn ready_reason() -> Option<String> {
    let reason = status_jsonpath("{.status.conditions[?(@.type==\"Ready\")].reason}");
    if reason.is_empty() {
        None
    } else {
        Some(reason)
    }
}

/// Bumps `spec.requeueAfterSeconds` by one and returns the resulting `metadata.generation`.
///
/// `requeueAfterSeconds` is deliberately **not** part of `source_spec_hash`, so the bump forces a
/// full reconcile while the diff gate still decides to skip — and the new generation is the
/// "this pass started after my snapshot" signal the zero-write assertion needs.
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

/// Reads `.data.key` of a fixture ConfigMap.
fn configmap_data_key(name: &str) -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        "configmap",
        name,
        "-n",
        TARGET_NAMESPACE,
        "-o",
        "jsonpath={.data.key}",
    ])
}

/// Edits `.data.key` of a fixture ConfigMap (drift injection).
fn patch_configmap_data_key(name: &str, value: &str) {
    let patch = format!(r#"{{"data":{{"key":"{value}"}}}}"#);
    let output = kubectl(&[
        "patch",
        "configmap",
        name,
        "-n",
        TARGET_NAMESPACE,
        "--type=merge",
        "-p",
        &patch,
    ]);
    assert!(
        output.status.success(),
        "drifting ConfigMap {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

fn synced_revision() -> Option<String> {
    let revision = status_jsonpath("{.status.sync.revision}");
    if revision.is_empty() {
        None
    } else {
        Some(revision)
    }
}

fn application_ready() -> bool {
    status_jsonpath("{.status.conditions[?(@.type==\"Ready\")].status}") == "True"
}

/// Polls `condition` until it holds or `budget` elapses.
///
/// A bounded retry loop (never a fixed `sleep`) keeps the test deterministic on a slow laptop
/// while still failing loudly instead of hanging.
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
