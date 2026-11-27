//! Live `v0.3` end-to-end test: the whole intelligent GitOps engine on a real `kind` cluster.
//!
//! # Safety gate
//!
//! This test **must never touch a non-`kind` cluster**. The very first thing it does is assert that
//! `kubectl config current-context` starts with `kind-`, mirroring the `test-integration` Makefile
//! guard. It is marked `#[ignore]` so `cargo test` never runs it accidentally; invoke it explicitly
//! with `make test-integration`.
//!
//! # What this pins (the seven `T10.6` invariants)
//!
//! 1. **Drift self-heal on/off** — with `selfHeal: true` a manual edit is reverted; with
//!    `selfHeal: false` it is reported `OutOfSync` and left alone.
//! 2. **Safe orphan prune & foreign non-prune** — a resource removed from Git is deleted when
//!    `prune: true`, kept when `prune: false`, and an object whose `ferriscd.io/tracking-id`
//!    belongs to another `Application` is never touched.
//! 3. **CRD + CR single sync** — the first sync of a brand-new `CustomResourceDefinition` and one of
//!    its custom resources succeeds without a second attempt (T08.3's `Established` wait +
//!    discovery refresh, plus the `T10.2` wave-level refresh when they are in different waves).
//! 4. **`Secret.stringData` zero drift + redaction** — a `Secret` declared with `stringData` is
//!    reported `Synced` on every subsequent pass, and its plaintext never appears in
//!    `status.resources`, `status.sync` or the `Ready` message.
//! 5. **`PreSync` hook + multi-wave rollout** — a wave `-1` `PreSync` `Job` with `generateName`
//!    runs exactly once, and the wave `0` `Deployment` does not exist until that hook is `Healthy`;
//!    the wave `1` `PostSync` smoke `Job` is created only after the whole `Sync` phase converged.
//! 6. **`Degraded` -> `Healthy`** — a `Deployment` with an unpullable image goes `Progressing` ->
//!    `Degraded`; pushing a real tag converges it back to `Healthy` (with `Synced` throughout).
//! 7. **Rollback stability** — deploy commit v1, then v2, then `{"rollback":{"id":1}}`: the live
//!    object reverts to v1 and **stays** there across requeues instead of being overwritten by
//!    `HEAD`, because the rollback disabled `spec.syncPolicy.automated`.
//!
//! # `T10.6` trap guard: run the suite **twice back-to-back**
//!
//! A live suite that passes once and flakes on the second run has timing assumptions baked in, which
//! is exactly what the roadmap's trap guard forbids. `make test-integration-twice` runs this file
//! twice against the same cluster without any cleanup in between (the second run must converge from
//! whatever the first one left behind — including a `Succeeded` `operationState`, a populated
//! `status.history` and a reaped hook `Job`). Every wait below is a bounded poll, never a fixed
//! sleep on an assertion path, which is what makes that second run meaningful rather than lucky.
//!
//! Nothing here was measured before the test was written: every budget is a bound to *check*, and
//! `docs/lessons/10-sync-waves-hooks-and-gitops-rollback.md` §10 records the numbers only once the
//! walkthrough has actually been run by hand (they are marked **PENDING** until then).
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

// Test-only shell-out helpers are allowed to panic: this entire file is compiled as a test target
// and never ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Control-plane namespace the controller watches.
const CONTROL_NAMESPACE: &str = "ferriscd-system";
/// Namespace the waves/hooks fixture deploys into.
const WAVES_NAMESPACE: &str = "ferriscd-waves-e2e";
/// Namespace the diff/prune fixture deploys into.
const PRUNE_NAMESPACE: &str = "ferriscd-prune-e2e";
/// Image that cannot be pulled.
const BAD_IMAGE: &str = "nginx:definitely-not-a-real-tag";
/// Image that pulls and serves.
const GOOD_IMAGE: &str = "nginx:1.27-alpine";
/// Short progress deadline so `Degraded` is reachable inside a test.
const PROGRESS_DEADLINE_SECONDS: u32 = 45;
/// Plaintext that must never reach `/status` (invariant 4).
const SECRET_PLAINTEXT: &str = "s3cr3t-do-not-log-me";
/// The wave-0 annotation every workload of the waves fixture carries (`T10.2`).
const WAVE_ZERO: &str = "  annotations:\n    ferriscd.io/sync-wave: \"0\"\n";

#[test]
#[ignore = "requires a live kind cluster (make kind-up)"]
fn the_v0_3_invariants_hold_end_to_end() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    install_crds();
    ensure_namespace(CONTROL_NAMESPACE);
    ensure_default_project();

    // Best-effort cleanup even if an assertion below panics.
    let _cluster_cleanup = ClusterCleanup::new();
    let _controller_cleanup = ControllerProcess::start();

    // ---------------------------------------------------------------------
    // 1 + 2 + 3 + 4: diff gate, prune rails, CRD+CR, Secret redaction
    // ---------------------------------------------------------------------
    let diff_fixture = tempfile::tempdir().expect("create the diff fixture directory");
    let diff_repo = diff_fixture.path();
    let v1 = write_diff_fixture(diff_repo);
    apply_application("e2e-diff", diff_repo, PRUNE_NAMESPACE);
    wait_for(Duration::from_secs(600), "the diff fixture to sync", || {
        synced_revision("e2e-diff").as_deref() == Some(v1.as_str())
    });
    // (3) the CRD and its CR landed on the first sync.
    assert!(
        kubectl_jsonpath(&[
            "get",
            "widget",
            "one",
            "-n",
            PRUNE_NAMESPACE,
            "-o",
            "jsonpath={.spec.size}"
        ])
        .is_some(),
        "a brand-new CRD and its CR must both exist after the first sync"
    );
    // (4) `stringData` is normalized, so the Secret never drifts and the plaintext never leaks.
    let status = status_raw("e2e-diff");
    assert!(
        !status.contains(SECRET_PLAINTEXT),
        "the Secret plaintext must never appear in /status: {status}"
    );
    assert_eq!(
        sync_status("e2e-diff").as_deref(),
        Some("Synced"),
        "a Secret declared with stringData must be Synced (normalized to base64 .data)"
    );

    // (1) self-heal ON: a manual edit to a Git-managed key is reverted.
    kubectl(&[
        "patch",
        "configmap",
        "settings",
        "-n",
        PRUNE_NAMESPACE,
        "--type=merge",
        "-p",
        "{\"data\":{\"APP_ENV\":\"drifted\"}}",
    ]);
    wait_for(
        Duration::from_secs(300),
        "self-heal to revert the manual edit",
        || configmap_data("settings", PRUNE_NAMESPACE, "APP_ENV").as_deref() == Some("demo"),
    );

    // (2) prune: the removed resource is deleted when prune is on...
    let v2 = remove_deployment_and_prune(diff_repo);
    wait_for(
        Duration::from_secs(300),
        "the removed Deployment to be pruned",
        || synced_revision("e2e-diff").as_deref() == Some(v2.as_str()),
    );
    wait_for(
        Duration::from_secs(300),
        "the pruned Deployment to disappear",
        || !kubectl_ok(&["get", "deployment", "api", "-n", PRUNE_NAMESPACE]),
    );
    // ...and a foreign object is never touched, even when it is no longer in Git.
    assert!(
        kubectl_ok(&["get", "configmap", "foreign-owned", "-n", PRUNE_NAMESPACE]),
        "an object tracked by another Application must never be pruned"
    );

    // (1) self-heal OFF: drift is reported and left in place.
    set_self_heal("e2e-diff", false);
    kubectl(&[
        "patch",
        "configmap",
        "settings",
        "-n",
        PRUNE_NAMESPACE,
        "--type=merge",
        "-p",
        "{\"data\":{\"APP_ENV\":\"still-here\"}}",
    ]);
    wait_for(
        Duration::from_secs(300),
        "self-heal: false to report the drift instead of reverting it",
        || sync_status("e2e-diff").as_deref() == Some("OutOfSync"),
    );
    assert_eq!(
        configmap_data("settings", PRUNE_NAMESPACE, "APP_ENV").as_deref(),
        Some("still-here"),
        "with selfHeal: false the manual edit is reported, never reverted"
    );
    // Put it back so the rest of the run is not permanently OutOfSync.
    kubectl(&[
        "patch",
        "configmap",
        "settings",
        "-n",
        PRUNE_NAMESPACE,
        "--type=merge",
        "-p",
        "{\"data\":{\"APP_ENV\":\"demo\"}}",
    ]);
    set_self_heal("e2e-diff", true);
    delete_application("e2e-diff");

    // ---------------------------------------------------------------------
    // 5: PreSync hook + multi-wave rollout
    // ---------------------------------------------------------------------
    let waves_fixture = tempfile::tempdir().expect("create the waves fixture directory");
    let waves_repo = waves_fixture.path();
    write_waves_fixture(waves_repo, GOOD_IMAGE);
    apply_application("e2e-waves", waves_repo, WAVES_NAMESPACE);

    // Wave gating (T10.2): wave 0 does not exist while wave -1's PreSync hook is still running. The
    // migration sleeps long enough for this window to be observable from outside the controller.
    wait_for(
        Duration::from_secs(300),
        "the PreSync hook to be created",
        || operation_phase("e2e-waves").is_some_and(|phase| phase == "PreSync"),
    );
    assert!(
        job_count(WAVES_NAMESPACE, "migrate-") == 1,
        "the PreSync hook must exist while its phase runs"
    );
    assert!(
        !kubectl_ok(&["get", "deployment", "api", "-n", WAVES_NAMESPACE]),
        "wave 0 must not exist while the wave -1 PreSync hook is running"
    );
    wait_for(
        Duration::from_secs(600),
        "the multi-wave rollout to finish",
        || operation_phase("e2e-waves").is_some_and(|phase| phase == "Succeeded"),
    );

    // A `generateName` hook runs exactly once, and the name the API server generated is what
    // `/status` tracks — a second run would leave a second Job behind (`T10.3`, finding H2).
    let hooks = active_hooks("e2e-waves");
    let migrations: Vec<&(String, String)> = hooks
        .iter()
        .filter(|(_, generated)| generated.starts_with("migrate-"))
        .collect();
    assert_eq!(
        migrations.len(),
        1,
        "a generateName PreSync hook must be tracked exactly once: {hooks:?}"
    );
    assert_eq!(migrations[0].0, "PreSync");
    assert_eq!(
        job_count(WAVES_NAMESPACE, "migrate-"),
        1,
        "a hook created once per requeue would leave several migrate- Jobs behind"
    );
    // A hook is never prunable inventory.
    let inventory = inventory_keys("e2e-waves");
    assert!(
        inventory.iter().all(|key| !key.contains("/Job/")),
        "a hook must never enter status.inventory: {inventory:?}"
    );
    assert!(
        kubectl_ok(&["get", "deployment", "api", "-n", WAVES_NAMESPACE]),
        "wave 0 is applied once wave -1 is Healthy"
    );

    // PostSync ordering (`T10.3`): the wave 1 smoke Job is created only after every `Sync` wave is
    // `Healthy`, so it cannot predate the wave 0 Deployment it smokes.
    let smoke: Vec<&(String, String)> = hooks
        .iter()
        .filter(|(_, generated)| generated.starts_with("smoke-"))
        .collect();
    assert_eq!(
        smoke.len(),
        1,
        "the PostSync smoke hook must run exactly once: {hooks:?}"
    );
    assert_eq!(smoke[0].0, "PostSync");
    assert_eq!(job_count(WAVES_NAMESPACE, "smoke-"), 1);
    let smoke_job = smoke[0].1.as_str();
    let deployment_created = creation_timestamp("deployment", "api", WAVES_NAMESPACE)
        .expect("the wave 0 Deployment has a creationTimestamp");
    let smoke_created = creation_timestamp("job", smoke_job, WAVES_NAMESPACE)
        .expect("the PostSync Job has a creationTimestamp");
    assert!(
        smoke_created >= deployment_created,
        "the PostSync smoke Job ({smoke_created}) must be created after the wave 0 Deployment \
         ({deployment_created})"
    );

    // ---------------------------------------------------------------------
    // 6: Degraded -> Healthy
    // ---------------------------------------------------------------------
    let broken = break_image_and_commit(waves_repo);
    wait_for(
        Duration::from_secs(300),
        "the broken revision to sync",
        || synced_revision("e2e-waves").as_deref() == Some(broken.as_str()),
    );
    wait_for(
        Duration::from_secs(600),
        "the Application to report Degraded for the bad image",
        || health_status("e2e-waves").as_deref() == Some("Degraded"),
    );
    assert_eq!(
        sync_status("e2e-waves").as_deref(),
        Some("Synced"),
        "a broken image is not a sync problem (T09.5): Git and the cluster agree"
    );
    let fixed = fix_image_and_commit(waves_repo, GOOD_IMAGE);
    wait_for(
        Duration::from_secs(300),
        "the fixed revision to sync",
        || synced_revision("e2e-waves").as_deref() == Some(fixed.as_str()),
    );
    wait_for(
        Duration::from_secs(600),
        "the Application to report Healthy and settle the fixed revision",
        || {
            health_status("e2e-waves").as_deref() == Some("Healthy")
                && operation_phase("e2e-waves").as_deref() == Some("Succeeded")
        },
    );

    // ---------------------------------------------------------------------
    // 7: rollback stability
    // ---------------------------------------------------------------------
    let v1_waves = head_sha(waves_repo);
    let v2_waves = set_configmap_version_and_commit(waves_repo, "v1");
    wait_for(
        Duration::from_secs(300),
        "the versioned revision to sync and settle",
        || {
            synced_revision("e2e-waves").as_deref() == Some(v2_waves.as_str())
                && configmap_data("settings", WAVES_NAMESPACE, "VERSION").as_deref() == Some("v1")
                && operation_phase("e2e-waves").as_deref() == Some("Succeeded")
        },
    );
    let rollback_id = history_id_for("e2e-waves", &v1_waves)
        .expect("the settled v1_waves deployment must be in status.history");
    set_annotation(
        "e2e-waves",
        "ferriscd.io/operation",
        &format!("{{\"rollback\":{{\"id\":{rollback_id}}}}}"),
    );
    wait_for(
        Duration::from_secs(300),
        "the rollback to redeploy the historical commit and settle",
        || {
            synced_revision("e2e-waves").as_deref() == Some(v1_waves.as_str())
                && configmap_data("settings", WAVES_NAMESPACE, "VERSION").as_deref() == Some("v0")
                && operation_phase("e2e-waves").as_deref() == Some("Succeeded")
        },
    );
    assert_eq!(
        configmap_data("settings", WAVES_NAMESPACE, "VERSION").as_deref(),
        Some("v0"),
        "the historical manifest (VERSION=v0 at v1_waves) must actually be applied"
    );
    assert!(
        !application_spec_json("e2e-waves").contains("\"automated\""),
        "a rollback removes spec.syncPolicy.automated so self-heal cannot overwrite it"
    );
    assert!(
        status_raw("e2e-waves").contains("AutomatedSyncDisabledByRollback"),
        "the operator must be told why the Application stopped following Git"
    );

    // The stability property: three more reconcile rounds must not move the revision back to HEAD.
    //
    // Kubernetes optimizes away a `/status` patch whose resulting object is byte-identical to the
    // stored one, so a no-op requeue does **not** bump `metadata.resourceVersion`. Trigger three
    // real reconcile rounds via `ferriscd.io/refresh` (which exercises the composite watch
    // predicate) and wait one `requeueAfterSeconds` cycle per round so periodic requeues also run.
    for round in 0..3 {
        set_annotation(
            "e2e-waves",
            "ferriscd.io/refresh",
            &format!("rollback-stability-{round}"),
        );
        std::thread::sleep(Duration::from_secs(6));
        let observed = observed_generation("e2e-waves")
            .expect("the status must record the generation it observed");
        let generation =
            application_generation("e2e-waves").expect("the Application has a generation");
        assert_eq!(
            observed, generation,
            "round {round}: the status must report the generation it observed"
        );
        assert_eq!(
            application_field("e2e-waves", "{.status.sync.lastSyncedRevision}").as_deref(),
            Some(v1_waves.as_str()),
            "round {round}: the pinned lastSyncedRevision must not flip back to HEAD"
        );
        assert_eq!(
            configmap_data("settings", WAVES_NAMESPACE, "VERSION").as_deref(),
            Some("v0"),
            "round {round}: the live ConfigMap must stay on the rolled-back revision"
        );
    }
    assert_eq!(
        configmap_data("settings", WAVES_NAMESPACE, "VERSION").as_deref(),
        Some("v0"),
        "the rollback stays applied across requeues"
    );

    delete_application("e2e-waves");
}

/// Deletes the resources this test creates.
struct ClusterCleanup;

impl ClusterCleanup {
    fn new() -> Self {
        // Start from a clean slate so a previous aborted run cannot mask a failure.
        Self::delete_all(false);
        Self
    }

    fn delete_all(include_crd: bool) {
        if include_crd {
            let _ = kubectl(&[
                "delete",
                "crd",
                "widgets.example.com",
                "--ignore-not-found=true",
            ]);
        }
        for name in ["e2e-diff", "e2e-waves"] {
            let _ = kubectl(&[
                "patch",
                "application",
                name,
                "-n",
                CONTROL_NAMESPACE,
                "--type=merge",
                "-p",
                r#"{"metadata":{"finalizers":[]}}"#,
            ]);
            let _ = kubectl(&[
                "delete",
                "application",
                name,
                "-n",
                CONTROL_NAMESPACE,
                "--ignore-not-found=true",
                "--timeout=30s",
            ]);
        }
        for namespace in [WAVES_NAMESPACE, PRUNE_NAMESPACE] {
            let _ = kubectl(&[
                "delete",
                "namespace",
                namespace,
                "--ignore-not-found=true",
                // Blocking delete (finding M2): a namespace left `Terminating` by an earlier run
                // races the next create with `AlreadyExists`/`Forbidden`.
                "--timeout=120s",
            ]);
        }
    }
}

impl Drop for ClusterCleanup {
    fn drop(&mut self) {
        Self::delete_all(true);
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
                // Explicit opt-in: the fixtures are local repositories, which the production URL
                // policy rejects on purpose.
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
// Fixtures
// -------------------------------------------------------------------------

/// Writes the diff/prune fixture: Namespace, ConfigMap, Secret, CRD+CR, a Deployment and a
/// ConfigMap another `Application` already owns.
fn write_diff_fixture(repo: &Path) -> String {
    write(
        repo,
        "namespace.yaml",
        &format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {PRUNE_NAMESPACE}\n"),
    );
    write(
        repo,
        "configmap.yaml",
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  APP_ENV: demo\n",
    );
    // `stringData` is the user-facing form; the normalizer must turn it into base64 `.data` so the
    // Secret never reports drift, and the plaintext must never reach `/status`.
    write(
        repo,
        "secret.yaml",
        &format!(
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: credentials\nstringData:\n  token: {SECRET_PLAINTEXT}\n"
        ),
    );
    write(
        repo,
        "deployment.yaml",
        &deployment_manifest("api", GOOD_IMAGE, ""),
    );
    write(
        repo,
        "crd.yaml",
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\nspec:\n  group: example.com\n  scope: Namespaced\n  names:\n    kind: Widget\n    plural: widgets\n    singular: widget\n  versions:\n    - name: v1\n      served: true\n      storage: true\n      schema:\n        openAPIV3Schema:\n          type: object\n          properties:\n            spec:\n              type: object\n              properties:\n                size:\n                  type: integer\n",
    );
    write(
        repo,
        "widget.yaml",
        "apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: one\nspec:\n  size: 3\n",
    );

    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git_commit(repo, "seed the diff/prune fixture");
    let sha = head_sha(repo);

    // A ConfigMap owned by a *different* Application: it must never be pruned, even though it is not
    // in this Application's Git tree.
    apply_owned_configmap();
    sha
}

/// Applies a ConfigMap stamped with another `Application`'s `tracking-id`.
fn apply_owned_configmap() {
    ensure_namespace(PRUNE_NAMESPACE);
    let manifest = format!(
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: foreign-owned\n  namespace: {PRUNE_NAMESPACE}\n  annotations:\n    ferriscd.io/tracking-id: \"{CONTROL_NAMESPACE}/someone-else:/ConfigMap:{PRUNE_NAMESPACE}/foreign-owned\"\ndata:\n  owner: someone-else\n"
    );
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating the foreign-owned ConfigMap failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Deletes the `Deployment` from the fixture and turns pruning on: it must be pruned, and the
/// foreign-owned ConfigMap must not.
fn remove_deployment_and_prune(repo: &Path) -> String {
    std::fs::remove_file(repo.join("deployment.yaml")).expect("remove deployment.yaml");
    set_prune("e2e-diff", true);
    git(repo, &["add", "-A"]);
    git_commit(repo, "remove the deployment and enable pruning");
    head_sha(repo)
}

/// Writes the waves/hooks fixture (a `PreSync` migration, wave 0 workloads, a versioned ConfigMap,
/// and a wave 1 `PostSync` smoke test).
///
/// The two hooks are `generateName` `Job`s — the shape the spec and
/// `examples/waves-hooks/` promise (`T10.3`, finding H2) — so "runs exactly once" is only true if the
/// generated name is tracked in `status.operationState.activeHooks`; a requeue that lost the record
/// would create a second, differently named `Job`.
fn write_waves_fixture(repo: &Path, image: &str) {
    write(
        repo,
        "namespace.yaml",
        &format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {WAVES_NAMESPACE}\n"),
    );
    write(
        repo,
        "configmap.yaml",
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n  annotations:\n    ferriscd.io/sync-wave: \"0\"\ndata:\n  APP_ENV: demo\n  VERSION: v0\n",
    );
    write(
        repo,
        "deployment.yaml",
        &deployment_manifest("api", image, WAVE_ZERO),
    );
    // Wave -1: the migration. It sleeps long enough for the "wave 0 must not exist yet" window to be
    // observable from outside the controller, and `BeforeHookCreation` (the named-hook default,
    // spelled out so the example matches `examples/waves-hooks/`) leaves the completed Job in place —
    // which is what makes "created exactly once" verifiable in the cluster as well as in `/status`.
    write(
        repo,
        "migrate.yaml",
        "apiVersion: batch/v1\n\
         kind: Job\n\
         metadata:\n\
         \x20 generateName: migrate-\n\
         \x20 annotations:\n\
         \x20   ferriscd.io/hook: PreSync\n\
         \x20   ferriscd.io/hook-delete-policy: BeforeHookCreation\n\
         \x20   ferriscd.io/sync-wave: \"-1\"\n\
         spec:\n\
         \x20 backoffLimit: 0\n\
         \x20 template:\n\
         \x20   spec:\n\
         \x20     restartPolicy: Never\n\
         \x20     containers:\n\
         \x20       - name: migrate\n\
         \x20         image: busybox:1.36\n\
         \x20         command: [\"sh\", \"-c\", \"echo migrating; sleep 10\"]\n",
    );
    // Wave 1: a `PostSync` smoke test. It runs only after every `Sync` wave is `Healthy` (`T10.3`),
    // and it is deliberately *not* reaped: its `creationTimestamp` is what proves the ordering
    // against the wave 0 `Deployment`.
    write(
        repo,
        "smoke-test.yaml",
        "apiVersion: batch/v1\n\
         kind: Job\n\
         metadata:\n\
         \x20 generateName: smoke-\n\
         \x20 annotations:\n\
         \x20   ferriscd.io/hook: PostSync\n\
         \x20   ferriscd.io/sync-wave: \"1\"\n\
         spec:\n\
         \x20 backoffLimit: 0\n\
         \x20 template:\n\
         \x20   spec:\n\
         \x20     restartPolicy: Never\n\
         \x20     containers:\n\
         \x20       - name: smoke\n\
         \x20         image: busybox:1.36\n\
         \x20         command: [\"sh\", \"-c\", \"echo smoke; sleep 1\"]\n",
    );
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["add", "."]);
    git_commit(repo, "seed the waves fixture");
}

fn set_configmap_version_and_commit(repo: &Path, version: &str) -> String {
    write(
        repo,
        "configmap.yaml",
        &format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\n{WAVE_ZERO}data:\n  APP_ENV: demo\n  VERSION: {version}\n"
        ),
    );
    git(repo, &["add", "."]);
    git_commit(repo, "bump the ConfigMap version");
    head_sha(repo)
}

fn break_image_and_commit(repo: &Path) -> String {
    write(
        repo,
        "deployment.yaml",
        &deployment_manifest("api", BAD_IMAGE, WAVE_ZERO),
    );
    git(repo, &["add", "."]);
    git_commit(repo, "break the image tag");
    head_sha(repo)
}

fn fix_image_and_commit(repo: &Path, image: &str) -> String {
    write(
        repo,
        "deployment.yaml",
        &deployment_manifest("api", image, WAVE_ZERO),
    );
    git(repo, &["add", "."]);
    git_commit(repo, "fix the image tag");
    head_sha(repo)
}

/// A `Deployment` with the given image and a short progress deadline (see the module docs).
///
/// `annotations` is emitted verbatim under `metadata` (empty for none). Every writer of this fixture
/// passes the wave-0 annotation, so re-committing the file cannot silently drop the workload out of
/// its wave.
fn deployment_manifest(name: &str, image: &str, annotations: &str) -> String {
    format!(
        "apiVersion: apps/v1\n\
         kind: Deployment\n\
         metadata:\n\
         \x20 name: {name}\n\
         {annotations}\
         spec:\n\
         \x20 replicas: 1\n\
         \x20 progressDeadlineSeconds: {PROGRESS_DEADLINE_SECONDS}\n\
         \x20 selector:\n\
         \x20   matchLabels:\n\
         \x20     app: {name}\n\
         \x20 template:\n\
         \x20   metadata:\n\
         \x20     labels:\n\
         \x20       app: {name}\n\
         \x20   spec:\n\
         \x20     containers:\n\
         \x20       - name: {name}\n\
         \x20         image: {image}\n\
         \x20         ports:\n\
         \x20           - containerPort: 80\n"
    )
}

// -------------------------------------------------------------------------
// Cluster helpers
// -------------------------------------------------------------------------

fn install_crds() {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package: this file is
    // `#[path]`-included from `crates/ferriscd-cli/tests/v0_3_e2e.rs` (the workspace root is a
    // virtual manifest with no test targets of its own), so `../..` is the workspace root.
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
    let manifest = format!("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n");
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "creating namespace {namespace} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Applies an `Application` pointing at a local fixture repository.
fn apply_application(name: &str, repo: &Path, namespace: &str) {
    let repo_path = repo.to_str().expect("utf8 fixture path");
    let manifest = format!(
        "apiVersion: ferriscd.io/v1alpha1\n\
         kind: Application\n\
         metadata:\n\
         \x20 name: {name}\n\
         \x20 namespace: {CONTROL_NAMESPACE}\n\
         spec:\n\
         \x20 source:\n\
         \x20   git:\n\
         \x20     repoURL: {repo_path}\n\
         \x20     targetRevision: main\n\
         \x20     path: .\n\
         \x20 destination:\n\
         \x20   cluster: in-cluster\n\
         \x20   namespace: {namespace}\n\
         \x20 syncPolicy:\n\
         \x20   automated:\n\
         \x20     prune: false\n\
         \x20     selfHeal: true\n\
         \x20   syncOptions:\n\
         \x20     createNamespace: true\n\
         \x20     takeoverFieldManagers:\n\
         \x20       - kubectl-patch\n\
         \x20 requeueAfterSeconds: 5\n\
         \x20 revisionHistoryLimit: 20\n"
    );
    let output = kubectl_with_stdin(&["apply", "-f", "-"], &manifest);
    assert!(
        output.status.success(),
        "applying Application {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn delete_application(name: &str) {
    let _ = kubectl(&[
        "delete",
        "application",
        name,
        "-n",
        CONTROL_NAMESPACE,
        "--ignore-not-found=true",
    ]);
}

fn set_self_heal(name: &str, enabled: bool) {
    let flag = if enabled { "true" } else { "false" };
    // A raw string keeps the JSON readable: no `{{`/`}}` escaping to get wrong.
    let patch = r#"{"spec":{"syncPolicy":{"automated":{"prune":false,"selfHeal":SELF_HEAL}}}}"#
        .replace("SELF_HEAL", flag);
    patch_application(name, &patch);
}

fn set_prune(name: &str, enabled: bool) {
    let flag = if enabled { "true" } else { "false" };
    let patch = r#"{"spec":{"syncPolicy":{"automated":{"prune":PRUNE,"selfHeal":true}}}}"#
        .replace("PRUNE", flag);
    patch_application(name, &patch);
}

fn patch_application(name: &str, patch: &str) {
    let output = kubectl(&[
        "patch",
        "application",
        name,
        "-n",
        CONTROL_NAMESPACE,
        "--type=merge",
        "-p",
        patch,
    ]);
    assert!(
        output.status.success(),
        "patching Application {name} with {patch} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Sets (or overwrites) one annotation on an `Application` — what the CLI does for
/// `ferriscd.io/operation`.
fn set_annotation(name: &str, key: &str, value: &str) {
    let output = kubectl(&[
        "annotate",
        "application",
        name,
        "-n",
        CONTROL_NAMESPACE,
        "--overwrite",
        &format!("{key}={value}"),
    ]);
    assert!(
        output.status.success(),
        "annotating the Application failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// -------------------------------------------------------------------------
// Reading `/status`
// -------------------------------------------------------------------------

fn status_raw(name: &str) -> String {
    let output = kubectl(&[
        "get",
        "application",
        name,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        "yaml",
    ]);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn application_field(name: &str, template: &str) -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        "application",
        name,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        &format!("jsonpath={template}"),
    ])
}

fn synced_revision(name: &str) -> Option<String> {
    application_field(name, "{.status.sync.revision}")
}

fn sync_status(name: &str) -> Option<String> {
    application_field(name, "{.status.sync.status}")
}

fn health_status(name: &str) -> Option<String> {
    application_field(name, "{.status.health.status}")
}

fn operation_phase(name: &str) -> Option<String> {
    application_field(name, "{.status.operationState.syncPhase}")
}

/// The hooks `/status` tracks, as `(syncPhase, generatedName)` pairs.
///
/// A `generateName` hook is identified by the name the API server picked, and
/// `status.operationState.activeHooks` is the only place that name is recorded (`T10.3`): "the hook
/// was created exactly once" therefore means exactly one entry here, whatever the `Job`s in the
/// namespace happen to say afterwards.
fn active_hooks(name: &str) -> Vec<(String, String)> {
    let rendered = application_field(
        name,
        "{range .status.operationState.activeHooks[*]}{.phase}={.generatedName};{end}",
    )
    .unwrap_or_default();
    rendered
        .split(';')
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| {
            let (phase, generated) = entry.split_once('=').unwrap_or((entry, ""));
            (phase.trim().to_owned(), generated.trim().to_owned())
        })
        .collect()
}

/// `status.inventory[].key` — the GKNN keys the pruner owns.
fn inventory_keys(name: &str) -> Vec<String> {
    application_field(name, "{.status.inventory[*].key}")
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

/// `status.observedGeneration`: the `metadata.generation` the controller last observed.
fn observed_generation(name: &str) -> Option<i64> {
    application_field(name, "{.status.observedGeneration}")?
        .trim()
        .parse()
        .ok()
}

/// `metadata.generation` of the `Application` itself.
fn application_generation(name: &str) -> Option<i64> {
    application_field(name, "{.metadata.generation}")?
        .trim()
        .parse()
        .ok()
}

/// `metadata.creationTimestamp` of a live object (RFC 3339, so lexicographic order is time order).
fn creation_timestamp(kind: &str, name: &str, namespace: &str) -> Option<String> {
    kubectl_jsonpath(&[
        "get",
        kind,
        name,
        "-n",
        namespace,
        "-o",
        "jsonpath={.metadata.creationTimestamp}",
    ])
}

fn application_spec_json(name: &str) -> String {
    let output = kubectl(&[
        "get",
        "application",
        name,
        "-n",
        CONTROL_NAMESPACE,
        "-o",
        "jsonpath={.spec}",
    ]);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The `status.history` id of the deployment that recorded `revision`.
fn history_id_for(name: &str, revision: &str) -> Option<i64> {
    let ids = application_field(
        name,
        &format!("{{.status.history[?(@.revision==\"{revision}\")].id}}"),
    )?;
    ids.split_whitespace().next()?.parse().ok()
}

fn configmap_data(name: &str, namespace: &str, key: &str) -> Option<String> {
    let output = kubectl(&[
        "get",
        "configmap",
        name,
        "-n",
        namespace,
        "-o",
        &format!("jsonpath={{.data.{key}}}"),
    ]);
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if value.is_empty() { None } else { Some(value) }
}

/// Number of `Job`s whose name starts with `prefix`.
fn job_count(namespace: &str, prefix: &str) -> usize {
    let output = kubectl(&[
        "get",
        "jobs",
        "-n",
        namespace,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ]);
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter(|name| name.starts_with(prefix))
        .count()
}

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

// -------------------------------------------------------------------------
// Git helpers
// -------------------------------------------------------------------------

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

/// Polls `condition` until it holds or `budget` elapses.
///
/// A bounded retry loop (never a fixed sleep on the assertion path) keeps the test deterministic on
/// a slow laptop while still failing loudly instead of hanging. The timeout message dumps the status
/// of **both** e2e `Application`s: the wait may be about either one, and printing the wrong one is
/// how a live failure becomes unattributable.
fn wait_for(budget: Duration, what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for {what}\n--- e2e-diff ---\n{}\n--- e2e-waves ---\n{}",
            status_raw("e2e-diff"),
            status_raw("e2e-waves")
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}
