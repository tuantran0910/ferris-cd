//! Live `v1.1` sync-window test: `AppProject.spec.syncWindows` deployment governance (`T17.4`).
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. Its first statement asserts that `kubectl
//! config current-context` starts with `kind-`, mirroring the `test-integration` Makefile guard, and
//! the test is `#[ignore]`d so `cargo test` never runs it by accident. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v1_1_sync_windows -- --ignored --test-threads=1
//! ```
//!
//! # What this pins
//!
//! The roadmap's `T17.4` live acceptance criterion — *"an active deny window blocks automated sync
//! on Git push while preserving drift reporting, and resumes automatically once the window closes"*
//! — plus the three clauses of its **Trap Guard**:
//!
//! 1. **A blocked window blocks the push.** A `deny` window that is open at every instant is applied
//!    to the project and a new commit is pushed. The controller resolves the new revision, reports
//!    it, and applies **nothing**.
//! 2. **Drift is still reported.** `status.sync.status` is `OutOfSync` (with `prune: true` and an
//!    orphan in the diff, so this is not an "already synced, nothing to do" pass), and `Ready`
//!    stays `True` with `reason=SyncWindowActive` — a change freeze is governance, not a failure, so
//!    it must never flip `Ready=False` (which is what `T19.4`'s `on-sync-failed` notification
//!    keys on).
//! 3. **`lastSyncedRevision` is untouched and nothing is pruned.** The pushed commit removes a
//!    `ConfigMap` from Git. While the window is open the live object keeps the *old revision's*
//!    value, the removed `ConfigMap` still exists (a blocked pass must never prune), and
//!    `status.sync.lastSyncedRevision` is still the baseline commit. A spec change is then applied to
//!    the `Application` to force a *distinct* reconcile (`status.observedGeneration` advances) and
//!    the same three facts are re-asserted on it: the block is not a one-pass accident.
//! 4. **The window closes on its own schedule.** The always-open window is replaced by one that is
//!    open *now* and closes at a computed instant (`<minute> * * * *` for two minutes), and nothing
//!    else is touched afterwards. The push only lands at or after that instant — measured, not
//!    assumed — and the orphan is pruned then.
//!
//! # No sleeps on an assertion path
//!
//! Every wait is a bounded poll. The one place a *clock* is read is step 4, where the test has to
//! know when the window it configures will close; the same clock the controller runs on is read
//! with `date -u +%s`, and the resume instant it observes is compared against the boundary it
//! computed. Nothing is `sleep`ed and then hoped for: the assertion is "the sync happened *at or
//! after* the boundary", which a wrongly-unblocked sync fails immediately.
//!
//! # Prerequisites (manual)
//!
//! ```text
//! make kind-up
//! ```
//!
//! The test installs `deploy/crds` itself if they are missing, creates the control-plane and
//! destination namespaces, applies the shipped `default` project, and starts/stops the controller
//! binary as a child process.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and
// never ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Control-plane namespace the controller watches (`--namespace`).
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// The `AppProject` this test governs (never `default`, so the rest of the live suite is unaffected).
const PROJECT: &str = "sync-windows-e2e";
/// The `Application` bound to that project.
const APPLICATION: &str = "sync-windows-e2e";
/// Destination namespace of the fixture `ConfigMap`s.
const APP_NAMESPACE: &str = "ferriscd-syncwindows-e2e";
/// The key the fixture revisions differ on.
const VERSION_KEY: &str = "VERSION";
/// The `ConfigMap` the pushed commit removes from Git: it is the prune candidate.
const REMOVED_CONFIG_MAP: &str = "legacy";
/// Poll interval of every bounded wait.
const POLL: Duration = Duration::from_secs(2);

/// A `deny` window that is open at **every** instant: it fires every minute and each occurrence
/// lasts the seven-day maximum, so the newest occurrence is never older than a minute and its tail
/// always covers "now". Chosen deliberately: it cannot close during the test, so the blocked-state
/// assertions of steps 1–3 are not racing a boundary.
const ALWAYS_ACTIVE_DENY: &str = r#"    - kind: deny
      schedule: "* * * * *"
      duration: 7d
"#;

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn an_active_deny_window_blocks_git_sync_and_resumes_when_it_closes() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    install_crds();
    // Best-effort cleanup even if an assertion below panics. It runs *before* the namespaces below
    // are created (it deletes leftovers from an aborted run) and is dropped *after* the controller
    // (fields are dropped in reverse declaration order), so the controller is gone before the
    // objects it manages are deleted.
    let _cluster_cleanup = ClusterCleanup::new();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_namespace(APP_NAMESPACE);
    ensure_default_project();
    let _controller_cleanup = ControllerProcess::start();

    // ---------------------------------------------------------------------
    // 1. Baseline: an ungoverned project syncs v1 (two ConfigMaps, one of them a prune candidate)
    // ---------------------------------------------------------------------
    let fixture = tempfile::tempdir().expect("create the fixture repository directory");
    let repo = fixture.path();
    let v1 = write_governed_fixture(repo);
    apply_project(None);
    apply_application(repo);
    wait_for(
        Duration::from_secs(600),
        "the baseline revision to sync",
        || {
            sync_status().as_deref() == Some("Synced")
                && last_synced_revision().as_deref() == Some(v1.as_str())
                && configmap_version("settings").as_deref() == Some("v1")
                && configmap_version(REMOVED_CONFIG_MAP).as_deref() == Some("v1")
        },
    );

    // ---------------------------------------------------------------------
    // 2. Change freeze: an always-active deny window + a Git push that removes a ConfigMap
    // ---------------------------------------------------------------------
    apply_project(Some(ALWAYS_ACTIVE_DENY));
    let v2 = write_push_during_freeze(repo);

    // The controller must resolve the pushed commit (so the block is a *decision*, not a stale
    // checkout), refuse to apply it, and say so on the `Application`.
    wait_for(
        Duration::from_secs(300),
        "the controller to record the blocking window instead of syncing the pushed commit",
        || {
            synced_revision().as_deref() == Some(v2.as_str())
                && sync_status().as_deref() == Some("OutOfSync")
                && condition_reason().as_deref() == Some("SyncWindowActive")
        },
    );

    // Trap guard: the live cluster and the sync markers are untouched, and drift is *reported*.
    assert_eq!(
        condition_status().as_deref(),
        Some("True"),
        "a blocked sync window is governance, not a failure: Ready must stay True \
         (Ready=False would fire the on-sync-failed notification)"
    );
    let message = condition_message().unwrap_or_default();
    assert!(
        message.contains("deny sync window is active"),
        "the Ready message must name the blocking window: {message}"
    );
    assert!(
        message.contains("nothing was applied or pruned"),
        "the Ready message must say that the blocked pass mutated nothing: {message}"
    );
    assert_eq!(
        last_synced_revision().as_deref(),
        Some(v1.as_str()),
        "a blocked pass must never advance or clear lastSyncedRevision"
    );
    assert_eq!(
        configmap_version("settings").as_deref(),
        Some("v1"),
        "a blocked pass must not apply the pushed revision"
    );
    assert!(
        kubectl_ok(&["get", "configmap", REMOVED_CONFIG_MAP, "-n", APP_NAMESPACE]),
        "a blocked pass must never prune: {REMOVED_CONFIG_MAP} is gone from Git but must still exist"
    );
    assert_eq!(
        sync_status().as_deref(),
        Some("OutOfSync"),
        "drift detection is not suppressed by a blocked window"
    );

    // Force one *distinct* reconcile with a spec change and re-assert everything on it: the block has
    // to hold on every pass, not on the one that happened to observe the push.
    let generation = application_generation().expect("the Application has a generation");
    patch_requeue_after_seconds(6);
    wait_for(
        Duration::from_secs(300),
        "a second reconcile to observe the spec change while the window blocks",
        || {
            observed_generation() == Some(generation + 1)
                && sync_status().as_deref() == Some("OutOfSync")
                && condition_reason().as_deref() == Some("SyncWindowActive")
        },
    );
    assert_eq!(
        application_generation(),
        Some(generation + 1),
        "the spec patch is what forced the reconcile"
    );
    assert_eq!(
        last_synced_revision().as_deref(),
        Some(v1.as_str()),
        "the second blocked pass must not advance lastSyncedRevision either"
    );
    assert_eq!(configmap_version("settings").as_deref(), Some("v1"));
    assert!(
        kubectl_ok(&["get", "configmap", REMOVED_CONFIG_MAP, "-n", APP_NAMESPACE]),
        "the second blocked pass must not prune either"
    );

    // ---------------------------------------------------------------------
    // 3. The window closes by itself: the same push must land, with nothing else touched
    // ---------------------------------------------------------------------
    let (closing_window, window_closes_at) = window_closing_soon();
    apply_project(Some(&closing_window));
    // Nothing below edits the project or the Application again: the only thing that can let the
    // push through is the window closing.
    let resumed_at = wait_for_instant(
        Duration::from_secs(600),
        "the blocked push to land once the window closes",
        || {
            configmap_version("settings").as_deref() == Some("v2")
                && last_synced_revision().as_deref() == Some(v2.as_str())
        },
    );
    assert!(
        resumed_at >= window_closes_at,
        "the push landed at {resumed_at} but the deny window only closes at {window_closes_at}: \
         a blocked window must never be bypassed"
    );
    wait_for(
        Duration::from_secs(300),
        "the sync to settle on the resumed revision and prune the removed ConfigMap",
        || {
            sync_status().as_deref() == Some("Synced")
                && !kubectl_ok(&["get", "configmap", REMOVED_CONFIG_MAP, "-n", APP_NAMESPACE])
        },
    );
    assert_eq!(
        last_synced_revision().as_deref(),
        Some(v2.as_str()),
        "the resumed sync must settle on the pushed commit"
    );
    assert_eq!(configmap_version("settings").as_deref(), Some("v2"));
    assert_eq!(
        condition_reason().as_deref(),
        Some("SyncSucceeded"),
        "once the window closes the Application reports a normal sync again"
    );

    delete_application();
}

// -------------------------------------------------------------------------
// Fixture repository
// -------------------------------------------------------------------------

/// Writes the baseline commit: two `ConfigMap`s, both tracked by the `Application`.
///
/// `settings` carries the revision marker; `legacy` exists only to be removed by the next commit, so
/// "a blocked pass never prunes" is observable in the cluster (and not merely in `/status`).
fn write_governed_fixture(repo: &Path) -> String {
    write(
        repo,
        "settings.yaml",
        &format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  {VERSION_KEY}: v1\n"
        ),
    );
    write(
        repo,
        &format!("{REMOVED_CONFIG_MAP}.yaml"),
        &format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {REMOVED_CONFIG_MAP}\ndata:\n  {VERSION_KEY}: v1\n"
        ),
    );
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git_commit(repo, "seed the governed fixture");
    head_sha(repo)
}

/// Pushes the commit a change freeze must hold back: `settings` moves to `v2` and `legacy` is
/// deleted (so the diff has both an in-place change and an orphan to prune).
fn write_push_during_freeze(repo: &Path) -> String {
    write(
        repo,
        "settings.yaml",
        &format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  {VERSION_KEY}: v2\n"
        ),
    );
    std::fs::remove_file(repo.join(format!("{REMOVED_CONFIG_MAP}.yaml")))
        .expect("remove the prune candidate from the fixture");
    git(repo, &["add", "-A"]);
    git_commit(repo, "bump settings to v2 and drop the legacy ConfigMap");
    head_sha(repo)
}

/// A `deny` window that is open **now** and closes at a known instant.
///
/// Returns the YAML entry (already indented for `spec.syncWindows:`) and the UTC epoch second at
/// which it closes. The schedule is `<minute> * * * *` (fires once an hour, at the current UTC
/// minute) with a two-minute duration, so:
///
/// * it is open at every instant in `[minute:00, minute+2:00)` of the hour the test is in;
/// * the test only accepts a minute that is at most 20 s old (so at least 100 s of blocked time
///   remain to observe) and at most `55` (so the two-minute window never crosses the top of the
///   hour, which would change which minute fires next);
/// * after it closes, the next occurrence is ~58 minutes away, i.e. the resume the test observes is
///   the *close* of this window and nothing else.
///
/// Reading the clock here is deliberate and is the only clock read in this file: the boundary has to
/// be an instant the test can compare against, not a duration it sleeps for.
fn window_closing_soon() -> (String, i64) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let now = utc_epoch_seconds();
        let minute_of_hour = (now / 60) % 60;
        let second_of_minute = now % 60;
        if second_of_minute <= 20 && minute_of_hour <= 55 {
            let ends_at = (now / 60 + 2) * 60;
            let yaml = format!(
                "    - kind: deny\n      schedule: \"{minute_of_hour} * * * *\"\n      duration: 2m\n"
            );
            return (yaml, ends_at);
        }
        assert!(
            Instant::now() < deadline,
            "no UTC minute with enough headroom to open a two-minute deny window and observe it"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

// -------------------------------------------------------------------------
// Cluster teardown / controller process
// -------------------------------------------------------------------------

/// Deletes everything this test creates.
struct ClusterCleanup;

impl ClusterCleanup {
    fn new() -> Self {
        // Start from a clean slate so an aborted earlier run cannot mask a failure.
        Self::delete_all();
        Self
    }

    fn delete_all() {
        // A finalizer would block the delete while the controller is gone; drop it first (the
        // namespace delete below reaps whatever the cascade did not).
        let _ = kubectl(&[
            "patch",
            "application",
            APPLICATION,
            "-n",
            CONTROL_NAMESPACE,
            "--type=merge",
            "-p",
            r#"{"metadata":{"finalizers":[]}}"#,
        ]);
        let _ = kubectl(&[
            "delete",
            "application",
            APPLICATION,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
            "--timeout=30s",
        ]);
        let _ = kubectl(&[
            "delete",
            "appproject",
            PROJECT,
            "-n",
            CONTROL_NAMESPACE,
            "--ignore-not-found=true",
            "--timeout=30s",
        ]);
        let _ = kubectl(&[
            "delete",
            "namespace",
            APP_NAMESPACE,
            "--ignore-not-found=true",
            // Blocking delete: a namespace left `Terminating` by an earlier run races the next
            // create with `AlreadyExists`/`Forbidden`.
            "--timeout=120s",
        ]);
    }
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        Self::delete_all();
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
                // Explicit opt-in: the fixture is a local repository, which the production URL policy
                // rejects on purpose.
                "--allow-local-repos",
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

// -------------------------------------------------------------------------
// Cluster helpers
// -------------------------------------------------------------------------

fn install_crds() {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package: this file is
    // `#[path]`-included from `crates/ferriscd-cli/tests/v1_1_sync_windows.rs` (the workspace root is
    // a virtual manifest with no test targets of its own), so `../..` is the workspace root.
    let crds = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/crds");
    let output = kubectl(&["apply", "-f", &crds.display().to_string()]);
    assert!(
        output.status.success(),
        "kubectl apply -f deploy/crds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the shipped `default` `AppProject` (`T12.1`): a missing project is a terminal denial.
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
    let manifest = format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n");
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating namespace {namespace} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the governed `AppProject`, with (`Some`) or without (`None`) `spec.syncWindows`.
///
/// A full `apply` — never a strategic-merge `patch` — is what makes `None` *remove* a window the
/// test installed earlier: the manifest is the whole desired project, so there is no drift between
/// what the test believes the windows are and what the controller evaluates.
fn apply_project(windows: Option<&str>) {
    let windows = match windows {
        Some(windows) => format!("  syncWindows:\n{windows}"),
        None => String::new(),
    };
    let manifest = format!(
        "apiVersion: ferriscd.io/v1alpha1\n\
         kind: AppProject\n\
         metadata:\n\
         \x20 name: {PROJECT}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         spec:\n\
         \x20 description: T17.4 sync-window live acceptance fixture.\n\
         \x20 sourceRepos:\n\
         \x20   - \"*\"\n\
         \x20 destinations:\n\
         \x20   - cluster: in-cluster\n\
         \x20     namespace: {APP_NAMESPACE}\n\
         \x20 namespaceResourceWhitelist:\n\
         \x20   - group: \"*\"\n\
         \x20     kind: \"*\"\n\
         {windows}"
    );
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying AppProject {PROJECT} failed: {}\n{manifest}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies the `Application` that points at the fixture repository.
fn apply_application(repo: &Path) {
    let repo_path = repo.to_str().expect("utf8 fixture path");
    let manifest = format!(
        "apiVersion: ferriscd.io/v1alpha1\n\
         kind: Application\n\
         metadata:\n\
         \x20 name: {APPLICATION}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         spec:\n\
         \x20 project: {PROJECT}\n\
         \x20 source:\n\
         \x20   git:\n\
         \x20     repoURL: {repo_path}\n\
         \x20     targetRevision: main\n\
         \x20     path: .\n\
         \x20 destination:\n\
         \x20   cluster: in-cluster\n\
         \x20   namespace: {APP_NAMESPACE}\n\
         \x20 syncPolicy:\n\
         \x20   automated:\n\
         \x20     prune: true\n\
         \x20     selfHeal: true\n\
         \x20 requeueAfterSeconds: 5\n\
         \x20 revisionHistoryLimit: 20\n"
    );
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying Application {APPLICATION} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Bumps `spec.requeueAfterSeconds`, which advances `metadata.generation` and therefore forces a
/// reconcile that is *distinguishable* from the one that observed the push
/// (`status.observedGeneration`).
fn patch_requeue_after_seconds(seconds: u32) {
    let output = kubectl(&[
        "patch",
        "application",
        APPLICATION,
        "-n",
        CONTROL_NAMESPACE,
        "--type=merge",
        "-p",
        &format!(r#"{{"spec":{{"requeueAfterSeconds":{seconds}}}}}"#),
    ]);
    assert!(
        output.status.success(),
        "patching spec.requeueAfterSeconds failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn delete_application() {
    let _ = kubectl(&[
        "delete",
        "application",
        APPLICATION,
        "-n",
        CONTROL_NAMESPACE,
        "--ignore-not-found=true",
    ]);
}

// -------------------------------------------------------------------------
// Reading `/status`
// -------------------------------------------------------------------------

fn application_field(template: &str) -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        "application",
        APPLICATION,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={template}"),
    ])
}

/// `status.sync.revision`: the Git revision the last pass resolved (advances even when blocked).
fn synced_revision() -> Option<String> {
    application_field("{.status.sync.revision}")
}

/// `status.sync.lastSyncedRevision`: the revision a pass last **completed** a sync on.
fn last_synced_revision() -> Option<String> {
    application_field("{.status.sync.lastSyncedRevision}")
}

fn sync_status() -> Option<String> {
    application_field("{.status.sync.status}")
}

/// The `Ready` condition's reason (success, skip, governance, or failure).
fn condition_reason() -> Option<String> {
    application_field(r#"{.status.conditions[?(@.type=="Ready")].reason}"#)
}

fn condition_status() -> Option<String> {
    application_field(r#"{.status.conditions[?(@.type=="Ready")].status}"#)
}

fn condition_message() -> Option<String> {
    application_field(r#"{.status.conditions[?(@.type=="Ready")].message}"#)
}

fn observed_generation() -> Option<i64> {
    application_field("{.status.observedGeneration}")?
        .trim()
        .parse()
        .ok()
}

fn application_generation() -> Option<i64> {
    application_field("{.metadata.generation}")?
        .trim()
        .parse()
        .ok()
}

/// `data.<VERSION_KEY>` of a fixture `ConfigMap` (the live revision marker).
fn configmap_version(name: &str) -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        "configmap",
        name,
        "-n",
        APP_NAMESPACE,
        "-o",
        &format!("jsonpath={{.data.{VERSION_KEY}}}"),
    ])
}

/// The `Application` (and the live `ConfigMap`s) dumped on a timeout, so a live failure is
/// attributable instead of just red.
fn status_dump() -> String {
    let application = kubectl(&[
        "get",
        "application",
        APPLICATION,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        "yaml",
    ]);
    let project = kubectl(&[
        "get",
        "appproject",
        PROJECT,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        "yaml",
    ]);
    let configmaps = kubectl(&["get", "configmaps", "-n", APP_NAMESPACE, "-o", "yaml"]);
    format!(
        "--- application ---\n{}\n--- appproject ---\n{}\n--- configmaps ({APP_NAMESPACE}) ---\n{}",
        String::from_utf8_lossy(&application.stdout),
        String::from_utf8_lossy(&project.stdout),
        String::from_utf8_lossy(&configmaps.stdout)
    )
}

// -------------------------------------------------------------------------
// `kubectl` / `git`
// -------------------------------------------------------------------------

fn kubectl_ok(args: &[&str]) -> bool {
    kubectl(args).status.success()
}

fn kubectl_jsonpath(args: &[&str]) -> Option<String> {
    let output = kubectl(args);
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
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

/// The machine's UTC clock, in epoch seconds (`date` is the same clock the controller reads).
fn utc_epoch_seconds() -> i64 {
    let output = Command::new("date")
        .args(["-u", "+%s"])
        .output()
        .expect("date must run");
    assert!(
        output.status.success(),
        "date -u +%s failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("date -u +%s must print an integer")
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

// -------------------------------------------------------------------------
// Bounded waits
// -------------------------------------------------------------------------

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
            "timed out after {budget:?} waiting for {what}\n{}",
            status_dump()
        );
        std::thread::sleep(POLL);
    }
}

/// Like [`wait_for`], but returns the UTC epoch second at which the condition was observed.
///
/// The instant is read *after* the condition held, so it is never earlier than the mutation the
/// condition proved: comparing it with a window boundary answers "did this happen before the window
/// closed?" without ever sleeping for the boundary.
fn wait_for_instant(budget: Duration, what: &str, condition: impl Fn() -> bool) -> i64 {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return utc_epoch_seconds();
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for {what}\n{}",
            status_dump()
        );
        std::thread::sleep(POLL);
    }
}
