//! Live `v1.2` drift-watcher test: an out-of-band `kubectl edit` and `kubectl delete` of an
//! inventory `ConfigMap` must be healed in **less than 10 s** even though the `Application` asks for
//! a `600 s` requeue (`T18.2`).
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. It asserts that `kubectl config
//! current-context` begins with `kind-` before doing anything, and it is `#[ignore]`d so `cargo test`
//! never runs it. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v1_2_drift_watcher -- --ignored --test-threads=1
//! ```
//!
//! # What this pins
//!
//! 1. `--enable-drift-watcher` actually starts a metadata watch: the
//!    `ferriscd_drift_watcher_active_watches` gauge reaches `>= 1` and
//!    `ferriscd_drift_watcher_fallback_total` stays `0` (so the watch is not silently parked on a
//!    `403`; the test cluster's credentials are the admin kubeconfig, which is the point: RBAC is
//!    proven separately by `deploy/README.md` + the chart, not smuggled in here).
//! 2. An out-of-band `kubectl edit` of a managed `ConfigMap` converges back to the Git value in
//!    `< 10 s` — as a *drift* trigger, not a requeue: `spec.requeueAfterSeconds` is `600`.
//! 3. An out-of-band `kubectl delete` of that same `ConfigMap` is re-created in `< 10 s`. This is
//!    the end-to-end proof of the `Delete`-classification contract: a delete event repeats the
//!    object's last written `resourceVersion`, so only a recorded prune marker may suppress it —
//!    anything else and an external delete would be invisible forever (finding C1).
//!
//! Every wait is a bounded poll of the observable state, never a fixed sleep, and the child process
//! is killed on every exit path (a `Drop` guard), so a failing assertion cannot leak a controller.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and never
// ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Control-plane namespace this test owns: the controller watches only this one, so a stray
/// `Application` elsewhere can never be reconciled by the process under test.
const CONTROL_NAMESPACE: &str = "ferriscd-drift-watcher-e2e";
/// Namespace the fixture `Application` deploys into (created by the test, not by Git, so the first
/// reconcile applies the `ConfigMap` instead of deferring it on a missing namespace).
const TARGET_NAMESPACE: &str = "ferriscd-drift-watcher-target";
/// The `AppProject` the `Application` references (must live in the control-plane namespace).
const PROJECT: &str = "drift";
/// The `Application` under test.
const APPLICATION: &str = "payments";
/// The `ConfigMap` the test edits and deletes out of band.
const CONFIG_MAP: &str = "settings";
/// The Git value of `.data.key` (what a converging reconcile restores).
const GIT_VALUE: &str = "value";
/// `T18.2` acceptance criterion: heal within **less than** ten seconds.
const CONVERGENCE_SLA: Duration = Duration::from_secs(10);
/// How long the controller may take to sync the fixture and start its watch.
const STARTUP_BUDGET: Duration = Duration::from_secs(180);

/// `T18.2`: `--enable-drift-watcher` starts a metadata watch, and an out-of-band `kubectl edit` /
/// `kubectl delete` of a managed `ConfigMap` converges in `< 10 s` although the `Application` asks
/// for a `600 s` requeue.
#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn drift_watcher_heals_an_out_of_band_edit_and_delete_within_ten_seconds() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    install_crds();
    let _cleanup = ClusterCleanup::new();
    create_control_namespace();
    create_target_namespace();
    apply_project();

    let fixture = tempfile::tempdir().expect("create git fixture directory");
    let repo = fixture.path();
    write_fixture_and_commit(repo);
    apply_application(repo.to_str().expect("utf8 fixture path"));

    let metrics = free_address();
    let mut controller = ControllerProcess::start(metrics, "ConfigMap");

    // --- 1. The Application converges from Git ------------------------------------------------
    wait_for(
        STARTUP_BUDGET,
        "the fixture ConfigMap to be applied from Git",
        || configmap_data_key() == Some(GIT_VALUE.to_owned()),
    );
    wait_for(
        STARTUP_BUDGET,
        "status.inventory to report the ConfigMap",
        || inventory_contains(&gknn()),
    );
    wait_for(
        STARTUP_BUDGET,
        "the Application to report Ready=True",
        || condition_status("Ready") == Some("True".to_owned()),
    );
    assert_eq!(
        status_jsonpath("{.status.sync.status}"),
        "Synced",
        "a freshly synced Application must report Synced"
    );

    // --- 2. The watcher is actually running (and not parked) -----------------------------------
    wait_for(
        STARTUP_BUDGET,
        "the drift watcher to hold an active metadata watch",
        || metric(metrics, "ferriscd_drift_watcher_active_watches") >= Some(1.0),
    );
    assert_eq!(
        metric(
            metrics,
            "ferriscd_drift_watcher_fallback_total{reason=\"forbidden\"}"
        ),
        Some(0.0),
        "the metadata watch must not be refused: a permanent error would park it on the fallback"
    );
    let triggers_before = metric(metrics, "ferriscd_drift_watcher_triggers_total")
        .expect("the trigger counter is registered");

    // --- 3. An out-of-band `kubectl edit` is healed in < 10 s ----------------------------------
    edit_configmap_out_of_band();
    assert_eq!(
        configmap_data_key(),
        Some("drifted".to_owned()),
        "the out-of-band edit must be visible before waiting for the heal (otherwise the \
         assertion below would pass without any drift)"
    );
    assert!(
        configmap_app_hash().is_some(),
        "the edit must leave the ownership labels in place, or the watch event could not be \
         mapped to the Application and the heal would be unattributable"
    );
    let edit_start = Instant::now();
    wait_for(CONVERGENCE_SLA, "the edited ConfigMap to be healed", || {
        configmap_data_key() == Some(GIT_VALUE.to_owned())
    });
    println!(
        "T18.2: out-of-band edit healed in {:?} (requeueAfterSeconds is 600)",
        edit_start.elapsed()
    );
    // The heal is attributable: the drift trigger counter advanced, and Model 1 could not have run
    // (its requeue is 600 s).
    wait_for(CONVERGENCE_SLA, "the edit to be a drift trigger", || {
        metric(metrics, "ferriscd_drift_watcher_triggers_total")
            .is_some_and(|count| count > triggers_before)
    });
    let triggers_after_edit = metric(metrics, "ferriscd_drift_watcher_triggers_total")
        .expect("the trigger counter is registered");

    // --- 4. An out-of-band `kubectl delete` is re-created in < 10 s ----------------------------
    delete_configmap_out_of_band();
    assert!(
        !configmap_exists(),
        "the out-of-band delete must be visible before waiting for the heal"
    );
    let delete_start = Instant::now();
    wait_for(
        CONVERGENCE_SLA,
        "the deleted ConfigMap to be re-created",
        || configmap_exists() && configmap_data_key() == Some(GIT_VALUE.to_owned()),
    );
    println!(
        "T18.2: out-of-band delete healed in {:?} (requeueAfterSeconds is 600)",
        delete_start.elapsed()
    );
    assert_eq!(
        configmap_tracking_id().as_deref(),
        Some(tracking_id().as_str()),
        "the re-created object must be owned by this Application again"
    );

    // --- 5. The heal really came from the drift watcher --------------------------------------
    wait_for(CONVERGENCE_SLA, "the delete to be a drift trigger", || {
        metric(metrics, "ferriscd_drift_watcher_triggers_total")
            .is_some_and(|count| count > triggers_after_edit)
    });
    assert_eq!(
        metric(metrics, "ferriscd_drift_watcher_fallback_total"),
        Some(0.0),
        "no watch may have fallen back to periodic polling during the test"
    );

    controller.stop();
}

// ---------------------------------------------------------------------------
// Controller child process
// ---------------------------------------------------------------------------

struct ControllerProcess {
    child: Child,
}

impl ControllerProcess {
    /// Starts `ferriscd controller` with the `T18.2` flags.
    ///
    /// `--drift-watcher-kinds=ConfigMap` is deliberately restrictive: it is the operator lever the
    /// roadmap documents, and it keeps the process from watching the kinds this fixture never
    /// touches.
    fn start(metrics: SocketAddr, kinds: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ferriscd"))
            .args([
                "controller",
                "--namespace",
                CONTROL_NAMESPACE,
                // The fixture repository is a local path, which the production URL policy rejects
                // on purpose.
                "--allow-local-repos",
                "--metrics-addr",
                &metrics.to_string(),
                "--enable-drift-watcher",
                "--drift-watcher-kinds",
                kinds,
            ])
            .env("RUST_LOG", "info")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the ferriscd binary must start");
        Self { child }
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ControllerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// Cluster fixtures
// ---------------------------------------------------------------------------

/// Deletes everything this test creates, on every exit path.
struct ClusterCleanup;

impl ClusterCleanup {
    fn new() -> Self {
        Self::delete_all();
        Self
    }

    fn delete_all() {
        // Strip the finalizer first: before the controller starts (and on `Drop`, after it has been
        // killed) nothing clears `ferriscd.io/finalizer`, so a bare delete would block.
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "patch",
            "application",
            APPLICATION,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":[]}}"#,
        ]);
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "application",
            APPLICATION,
            "--ignore-not-found=true",
            "--timeout=30s",
        ]);
        for namespace in [TARGET_NAMESPACE, CONTROL_NAMESPACE] {
            let _ = kubectl(&[
                "delete",
                "namespace",
                namespace,
                "--ignore-not-found=true",
                // Blocking delete: a namespace left `Terminating` by an earlier run races the next
                // create with `AlreadyExists`.
                "--timeout=120s",
            ]);
        }
    }
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        Self::delete_all();
    }
}

fn current_kube_context() -> String {
    let output = kubectl(&["config", "current-context"]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn install_crds() {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package: this file is
    // `#[path]`-included from `crates/ferriscd-cli/tests/v1_2_drift_watcher.rs`, so `../..` is the
    // workspace root where `deploy/` lives.
    let crds = workspace_root().join("deploy/crds");
    for entry in std::fs::read_dir(&crds).expect("deploy/crds must exist") {
        let path = entry.expect("a CRD file").path();
        if path
            .extension()
            .is_some_and(|extension| extension == "yaml")
        {
            let output = kubectl(&["apply", "-f", &path.to_string_lossy()]);
            assert!(
                output.status.success(),
                "kubectl apply -f {} failed: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

fn create_control_namespace() {
    apply_stdin(&format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {CONTROL_NAMESPACE}\n"
    ));
}

fn create_target_namespace() {
    apply_stdin(&format!(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {TARGET_NAMESPACE}\n"
    ));
}

fn apply_project() {
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {PROJECT}
  namespace: {CONTROL_NAMESPACE}
spec:
  description: "drift watcher e2e (T18.2)"
  sourceRepos: ["*"]
  sourceNamespaces: ["{CONTROL_NAMESPACE}"]
  destinations:
    - cluster: in-cluster
      namespace: "*"
  allowedServiceAccounts: ["*"]
"#
    ));
}

/// Applies the `Application` CR that points at the local fixture repository.
///
/// `requeueAfterSeconds: 600` is the whole point: Model 1 would need ten minutes to notice the
/// out-of-band edit, so a heal inside ten seconds can only come from the drift watcher.
///
/// `takeoverFieldManagers` lists `kubectl-edit` and `kubectl-patch` because both legs of the test
/// mutate the `ConfigMap` as those field managers. FerrisCD never forces fields owned by another
/// manager (`serverSideForce` stays `false`), so without this opt-in self-heal would correctly
/// refuse and the test would time out — the refusal is the safe default, this field is the
/// documented escape hatch exercised here.
fn apply_application(repo_path: &str) {
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {APPLICATION}
  namespace: {CONTROL_NAMESPACE}
spec:
  project: {PROJECT}
  source:
    git:
      repoURL: {repo_path}
      targetRevision: main
      path: .
  destination:
    cluster: in-cluster
    namespace: {TARGET_NAMESPACE}
  syncPolicy:
    syncOptions:
      takeoverFieldManagers:
        - kubectl-edit
        - kubectl-patch
    automated:
      prune: false
      selfHeal: true
  requeueAfterSeconds: 600
"#
    ));
}

/// Writes the fixture repository (one `ConfigMap`) and commits it.
fn write_fixture_and_commit(repo: &Path) {
    std::fs::write(
        repo.join("configmap.yaml"),
        format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {CONFIG_MAP}\n  \
             namespace: {TARGET_NAMESPACE}\ndata:\n  key: {GIT_VALUE}\n"
        ),
    )
    .expect("write the fixture ConfigMap");

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
            "seed configmap",
        ],
    );
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
// Out-of-band mutations (`kubectl edit` / `kubectl delete`)
// ---------------------------------------------------------------------------

/// Edits the managed `ConfigMap` the way an operator would: `kubectl edit`.
///
/// `kubectl edit` shells out to `$KUBECTL_EDITOR` with the fetched object as the only argument, so
/// the "editor" is a two-line script that rewrites the file. The write therefore goes through
/// `kubectl edit`'s own patch (field manager `kubectl-edit`) — not through FerrisCD.
fn edit_configmap_out_of_band() {
    let fixture = tempfile::tempdir().expect("create an editor directory");
    let editor = fixture.path().join("editor.sh");
    // Only the data value changes: rewriting the whole file would drop the
    // `ferriscd.io/managed-by`/`ferriscd.io/app-hash` labels, and an unmappable event is exactly the
    // case the drift watcher cannot (and must not) trigger on.
    std::fs::write(
        &editor,
        "#!/bin/sh\nsed 's/^  key: value$/  key: drifted/' \"$1\" > \"$1.tmp\" && \
         mv \"$1.tmp\" \"$1\"\n",
    )
    .expect("write the editor script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&editor, std::fs::Permissions::from_mode(0o755))
            .expect("the editor script must be executable");
    }

    let mut command = Command::new("kubectl");
    command
        .args(["-n", TARGET_NAMESPACE, "edit", "configmap", CONFIG_MAP])
        // `kubectl edit` runs `$KUBECTL_EDITOR` (older clients) or `$EDITOR` (current clients, which
        // dropped the `KUBECTL_*` form) with the fetched object as the only argument. Both are set,
        // and `EDITOR`/`VISUAL` are overwritten explicitly so a developer's own editor can never be
        // launched (or quietly do nothing, which kubectl reports as "no changes made").
        .env("KUBECTL_EDITOR", &editor)
        .env("EDITOR", &editor)
        .env("VISUAL", &editor)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command.output().expect("kubectl edit must run");
    assert!(
        output.status.success(),
        "kubectl edit failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn delete_configmap_out_of_band() {
    let output = kubectl(&[
        "-n",
        TARGET_NAMESPACE,
        "delete",
        "configmap",
        CONFIG_MAP,
        "--ignore-not-found=true",
    ]);
    assert!(
        output.status.success(),
        "kubectl delete failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

fn gknn() -> String {
    format!("/ConfigMap/{TARGET_NAMESPACE}/{CONFIG_MAP}")
}

/// The `ferriscd.io/tracking-id` this Application stamps on the object:
/// `<app-namespace>/<app-name>:/<Kind>:<object-namespace>/<object-name>`.
fn tracking_id() -> String {
    format!("{CONTROL_NAMESPACE}/{APPLICATION}:/ConfigMap:{TARGET_NAMESPACE}/{CONFIG_MAP}")
}

fn configmap_app_hash() -> Option<String> {
    jsonpath(&[
        "-n",
        TARGET_NAMESPACE,
        "get",
        "configmap",
        CONFIG_MAP,
        "-o",
        "jsonpath={.metadata.labels.ferriscd\\.io/app-hash}",
    ])
}

fn configmap_exists() -> bool {
    kubectl(&[
        "-n",
        TARGET_NAMESPACE,
        "get",
        "configmap",
        CONFIG_MAP,
        "-o",
        "name",
    ])
    .status
    .success()
}

fn configmap_data_key() -> Option<String> {
    jsonpath(&[
        "-n",
        TARGET_NAMESPACE,
        "get",
        "configmap",
        CONFIG_MAP,
        "-o",
        "jsonpath={.data.key}",
    ])
}

fn configmap_tracking_id() -> Option<String> {
    jsonpath(&[
        "-n",
        TARGET_NAMESPACE,
        "get",
        "configmap",
        CONFIG_MAP,
        "-o",
        "jsonpath={.metadata.annotations.ferriscd\\.io/tracking-id}",
    ])
}

fn condition_status(condition: &str) -> Option<String> {
    jsonpath(&[
        "-n",
        CONTROL_NAMESPACE,
        "get",
        "application",
        APPLICATION,
        "-o",
        &format!("jsonpath={{.status.conditions[?(@.type==\"{condition}\")].status}}"),
    ])
}

fn status_jsonpath(template: &str) -> String {
    jsonpath(&[
        "-n",
        CONTROL_NAMESPACE,
        "get",
        "application",
        APPLICATION,
        "-o",
        &format!("jsonpath={template}"),
    ])
    .unwrap_or_default()
}

fn inventory_contains(key: &str) -> bool {
    status_jsonpath("{.status.inventory[*].key}")
        .split_whitespace()
        .any(|entry| entry == key)
}

// ---------------------------------------------------------------------------
// Shell & HTTP helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

fn apply_stdin(manifest: &str) {
    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("kubectl must start");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(manifest.as_bytes())
        .expect("the manifest is written");
    let output = child.wait_with_output().expect("kubectl output");
    assert!(
        output.status.success(),
        "kubectl apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn kubectl(args: &[&str]) -> Output {
    Command::new("kubectl")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("kubectl must run")
}

fn jsonpath(args: &[&str]) -> Option<String> {
    let output = kubectl(args);
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!value.is_empty()).then_some(value)
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    address
}

/// Reads one sample out of the process's `/metrics` endpoint, or `None` when it is not up yet.
///
/// `name` may carry a label selector (`metric{label="value"}`), which is matched literally: the
/// exposition never reorders or re-formats a fixed label set.
fn metric(address: SocketAddr, name: &str) -> Option<f64> {
    let (selector, labels) = match name.split_once('{') {
        Some((selector, labels)) => (selector, Some(labels)),
        None => (name, None),
    };
    let body = http_get(address)?;
    let mut total: Option<f64> = None;
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((series, value)) = line.rsplit_once(' ') else {
            continue;
        };
        let matches_labels = match labels {
            Some(labels) => series.starts_with(selector) && series.contains(labels),
            // No selector: the whole family (a labelled family has no unlabelled series).
            None => series == selector || series.starts_with(&format!("{selector}{{")),
        };
        if !matches_labels {
            continue;
        }
        if let Ok(parsed) = value.parse::<f64>() {
            total = Some(total.unwrap_or(0.0) + parsed);
        }
    }
    total
}

fn http_get(address: SocketAddr) -> Option<String> {
    let mut stream = TcpStream::connect(address).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    stream
        .write_all(
            format!("GET /metrics HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let text = String::from_utf8_lossy(&response);
    let status = text.split_whitespace().nth(1)?;
    if status != "200" {
        return None;
    }
    text.split_once("\r\n\r\n").map(|(_, body)| body.to_owned())
}

/// Polls `condition` until it holds or `budget` elapses.
///
/// A bounded retry loop, never a fixed sleep: it fails loudly with the observed `status` instead of
/// hanging, and it returns as soon as the cluster agrees.
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
        std::thread::sleep(Duration::from_millis(100));
    }
}
