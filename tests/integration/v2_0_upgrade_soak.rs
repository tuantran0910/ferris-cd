//! Live `v2.0` disaster-recovery and zero-downtime-upgrade suite (`T20.4`).
//!
//! Two stories, in the order an operator lives them:
//!
//! 1. [`a_v1_0_to_v2_0_upgrade_keeps_ten_workloads_running`] — install the **real `v1.0` CRDs**
//!    (frozen in `crates/ferriscd-crd/tests/fixtures/v1_0/crds/`), let ten `Application`s each
//!    converge a `Deployment`, then upgrade **CRDs first** (as `helm upgrade` requires) and roll the
//!    control plane to a second instance. The upgrade must cost **0** managed-workload pod restarts,
//!    **0** unintended deletes, an intact `status.inventory`, and a `/readyz`-gated hand-off (the new
//!    instance answers `503` until its own gates complete, while the old one still answers `200`).
//! 2. [`a_backup_bundle_round_trips_through_a_disaster_recovery_restore`] — `ferriscd backup export`
//!    / `restore`: the bundle carries no `Secret` material and no server-managed field, `--dry-run`
//!    and a real restore both work, a second restore is idempotent, and a missing credential
//!    `Secret` fails the pre-flight (unless explicitly allowed). It also pins the inventory's scope:
//!    a whole-cluster export records the control-plane namespace's credentials and **not** a
//!    labelled `Secret` in a tenant namespace (`H-NEW-1`), because the controller reads credentials
//!    through a namespaced `Api<Secret>` in its own namespace and nowhere else.
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. It asserts that `kubectl config
//! current-context` begins with `kind-` before doing anything, and both tests are `#[ignore]`d so
//! `cargo test` never needs a cluster. Invoke them with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v2_0_upgrade_soak -- --ignored
//! ```
//!
//! # Serial by construction, not by command line
//!
//! Both tests install and delete the FerrisCD CRDs, and deleting a CRD deletes **every custom
//! resource of that kind, cluster-wide** — so running the two at the same time would make one test's
//! `install_v1_0_crds`/`reset_ferriscd_crds` step destroy the other's fixtures, or delete the schema
//! the other one is mid-way through using. Serial execution is therefore **not** something the
//! operator opts into on the command line: `make test-integration` runs `cargo test --workspace --
//! --ignored`, which uses the default thread count. Both tests take the process-global `LIVE_SUITE`
//! mutex as their first statement, so they are serial under any thread count, and a parallel run is
//! equivalent to a serial one (the same arrangement `tests/integration/v0_5_notifications.rs` uses).
//!
//! # Prerequisites
//!
//! * a `kind` cluster from `make kind-up`;
//! * `git` and `kubectl` on `PATH`;
//! * the `registry:2` image available to the node (`kind load docker-image registry:2 --name
//!   ferriscd-dev`, or network access to pull it). The ten fixture `Deployment`s run it with
//!   `imagePullPolicy: IfNotPresent`, so the crash-loop-free `Running` state the restart assertions
//!   read is a real running container, not a pending pod.
//!
//! # Why this is not a `helm upgrade`
//!
//! This repository has no published `v1.0` image to pull, and a live suite must not depend on a
//! registry network. The upgrade therefore performs exactly the steps `helm upgrade` performs, in
//! the order the chart requires (CRDs via Server-Side Apply, then the control-plane rollout), and
//! the `helm` equivalents are spelled out in `docs/operations/RUNBOOK.md` §9. Everything the
//! acceptance criterion names — 0 restarts, 0 deletes, intact inventory, `/readyz` gating — is
//! measured here against the real API server.
//!
//! Every wait is a bounded poll of observable cluster state, never a fixed sleep, and every created
//! object plus every child process is cleaned up on all exit paths (`Drop` guards), so a run can
//! never be satisfied by a previous run's leftovers and is safe to repeat
//! (`make test-integration-twice`).

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and never
// ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

/// Namespaces the upgrade test owns (the controller watches only [`UPGRADE_NAMESPACE`]).
const UPGRADE_NAMESPACE: &str = "ferriscd-upgrade-e2e";
/// Namespace the ten fixture `Deployment`s are delivered to.
const UPGRADE_TARGET_NAMESPACE: &str = "ferriscd-upgrade-target";
/// The `AppProject` the ten `Application`s reference.
const UPGRADE_PROJECT: &str = "upgrade";
/// Number of managed workloads the upgrade must not disturb.
const WORKLOADS: usize = 10;
/// Prefix of each generated `Application` (and of its `Deployment`/`ConfigMap`).
const WORKLOAD_PREFIX: &str = "workload-";
/// `spec.requeueAfterSeconds` of every fixture `Application`: the soak window is two of these, so a
/// controller that re-applied unconditionally on every pass would be caught.
const REQUEUE_AFTER_SECONDS: u32 = 15;
/// The soak window: two full requeue periods.
const SOAK_WINDOW: Duration = Duration::from_secs(2 * REQUEUE_AFTER_SECONDS as u64 + 2);

/// Namespace the backup/restore test owns.
const BACKUP_NAMESPACE: &str = "ferriscd-backup-e2e";
/// The `AppProject` that test restores.
const BACKUP_PROJECT: &str = "payments";
/// The `Application`s that test restores.
const BACKUP_APPLICATIONS: [&str; 2] = ["payments-api", "payments-worker"];
/// The credential `Secret` that test exports a *stub* for and then removes.
const BACKUP_SECRET: &str = "payments-repo";
/// A value that must never appear in a bundle: it is what a naive exporter would write.
const BACKUP_SECRET_PASSWORD: &str = "s3cr3t-pa55word-never-in-a-bundle";
/// A **tenant** namespace that holds a decoy credential `Secret` (`H-NEW-1`).
///
/// FerrisCD reads every credential type it consumes from the control-plane namespace only (a
/// namespaced `Api<Secret>`; `T12.4`/`T13.1`/`T19.1`/`T19.4`), so a labelled `Secret` here is not a
/// credential a restore can depend on and a bundle must not record it — the review's
/// "`team-a/payments-repo`" scenario.
const BACKUP_TENANT_NAMESPACE: &str = "ferriscd-backup-tenant";
/// The decoy `Secret` in [`BACKUP_TENANT_NAMESPACE`]: labelled exactly like a real credential.
const BACKUP_TENANT_SECRET: &str = "tenant-only-repo";

/// How long a first convergence (image pull + first render) may take.
const STARTUP_BUDGET: Duration = Duration::from_secs(300);
/// How long a settle/rollout observation may take.
const CONVERGENCE_BUDGET: Duration = Duration::from_secs(240);
/// How long the new control-plane instance may take to report ready.
const READY_BUDGET: Duration = Duration::from_secs(120);

/// Serialises the two live tests **in this process**.
///
/// Both of them install (and delete) the FerrisCD CRDs, and deleting a CRD deletes every custom
/// resource of that kind across the whole cluster. `cargo test -- --ignored` (what
/// `make test-integration` runs) uses the default thread count, so the "run serially" note in the
/// module docs has to be enforced here rather than in the command line.
static LIVE_SUITE: Mutex<()> = Mutex::new(());

/// Takes the process-global live-suite lock.
fn live_suite() -> std::sync::MutexGuard<'static, ()> {
    acquire(&LIVE_SUITE)
}

/// Locks `lock`, recovering from a poisoning panic.
///
/// A panic *while holding* it poisons the mutex; the other live test must still run (and report its
/// own result) rather than fail on a `PoisonError` it cannot do anything about, and `()` carries no
/// state a panic could leave half-written, so recovering is sound. Taking the `&'static` argument
/// (instead of reading the global directly) is what lets a test prove the recovery without poisoning
/// the real lock.
fn acquire(lock: &'static Mutex<()>) -> std::sync::MutexGuard<'static, ()> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// **`T20.4` acceptance:** a `v1.0` → `v2.0` in-place upgrade disturbs nothing.
#[test]
#[ignore = "requires a live kind cluster (make kind-up), git, kubectl and a registry:2 image"]
fn a_v1_0_to_v2_0_upgrade_keeps_ten_workloads_running() {
    // First statement, before even the context check: the other live test in this file deletes every
    // FerrisCD CRD cluster-wide (which deletes every custom resource of that kind), so this is the
    // serialisation point.
    let _live = live_suite();
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    assert_binary("git", &["--version"]);

    let _cleanup = UpgradeCleanup::new();
    install_v1_0_crds();
    create_namespace(UPGRADE_NAMESPACE);
    create_namespace(UPGRADE_TARGET_NAMESPACE);

    // --- 0. A real Git repository with ten independent plain-YAML workloads --------------------
    let work = tempfile::tempdir().expect("create the fixture directory");
    let repository = work.path().join("fleet");
    write_fleet_repository(&repository);
    let repo_url = repository.to_str().expect("utf8 fixture path").to_owned();

    apply_project();
    apply_applications(&repo_url);

    // The `v1.0` schema admitted them: had the fixtures carried a `v2.0`-only field, this step would
    // have failed at admission and the whole comparison below would be meaningless.
    for index in 0..WORKLOADS {
        let name = workload_name(index);
        assert!(
            application_spec(UPGRADE_NAMESPACE, &name).is_some(),
            "{name} was not admitted by the installed v1.0 CRD"
        );
    }

    let mut old = ServerProcess::start(&format!("v1.0-baseline-{UPGRADE_NAMESPACE}"));
    let old_ready = wait_for_ready_gated(old.address);
    assert!(old_ready.contains(r#""status":"ready""#), "{old_ready}");

    // --- 1. v1.0 steady state: ten Synced/Healthy Applications over ten running pods -----------
    wait_for(
        STARTUP_BUDGET,
        "the ten v1.0 Applications to converge",
        || {
            (0..WORKLOADS).all(|index| {
                let name = workload_name(index);
                sync_status(&name).as_deref() == Some("Synced")
                    && health_status(&name).as_deref() == Some("Healthy")
            }) && running_pods() == WORKLOADS
        },
    );

    let pods_before = pod_snapshot();
    let inventory_before = inventory_snapshot();
    let objects_before = managed_object_snapshot();
    let history_before = history_lengths();
    assert_eq!(pods_before.len(), WORKLOADS, "ten pods must be running");
    for (pod, (uid, restarts, _)) in &pods_before {
        assert_eq!(*restarts, 0, "{pod} restarted before the upgrade");
        assert!(!uid.is_empty(), "{pod} has no uid");
    }
    for index in 0..WORKLOADS {
        let name = workload_name(index);
        let inventory = inventory_before
            .get(&name)
            .unwrap_or_else(|| panic!("{name} has no status.inventory"));
        assert_eq!(
            inventory.len(),
            2,
            "{name} must own its ConfigMap and Deployment, got {inventory:?}"
        );
    }

    // --- 2. Upgrade step 1: CRDs, exactly as `helm upgrade` requires them to go first ----------
    install_current_crds();
    // The current schema is really installed (non-vacuity for the upgrade itself).
    assert!(
        jsonpath(&[
            "get",
            "crd",
            "applications.ferriscd.io",
            "-o",
            "jsonpath={.spec.versions[0].schema.openAPIV3Schema.properties.spec.properties.sources.type}",
        ])
        .as_deref()
            == Some("array"),
        "the v2.0 Application schema (spec.sources) was not installed"
    );
    // ...and the stored `v1.0` objects survived it untouched.
    for index in 0..WORKLOADS {
        let name = workload_name(index);
        let spec = application_spec(UPGRADE_NAMESPACE, &name)
            .unwrap_or_else(|| panic!("{name} disappeared when the CRD was upgraded"));
        assert!(
            spec.get("sources").is_none(),
            "{name}: upgrading the CRD must not rewrite the stored spec"
        );
        assert_eq!(
            spec["source"]["git"]["repoURL"].as_str(),
            Some(repo_url.as_str())
        );
        // `requeueAfterSeconds` is what bounds the soak below, so the whole "no churn" claim rests on
        // the upgraded schema still carrying it: a CRD change that dropped or defaulted it away would
        // silently turn the soak into a much tighter (or much looser) window while still passing.
        assert_eq!(
            spec["requeueAfterSeconds"].as_u64(),
            Some(u64::from(REQUEUE_AFTER_SECONDS)),
            "{name}: spec.requeueAfterSeconds did not survive the CRD upgrade: {spec}"
        );
    }

    // --- 3. Upgrade step 2: roll the control plane (new instance before the old one leaves) ----
    let mut new = ServerProcess::start(&format!("v2.0-rollout-{UPGRADE_NAMESPACE}"));
    // The new instance is admitted only once *its* gates complete. While it is unready the old one
    // must still answer `200`, which is what makes the rollout zero-downtime.
    let new_ready = wait_for_ready_gated_while_old_serves(new.address, old.address);
    assert!(new_ready.contains(r#""status":"ready""#), "{new_ready}");

    old.stop();

    // --- 4. The new instance is the live controller: it consumes a queued operation -------------
    request_operation(&workload_name(0));
    wait_for(
        CONVERGENCE_BUDGET,
        "the rolled control plane to consume the queued sync operation",
        || operation(&workload_name(0)).is_none(),
    );

    // --- 5. Soak: nothing may churn across two full requeue periods ----------------------------
    let deadline = Instant::now() + SOAK_WINDOW;
    while Instant::now() < deadline {
        assert_eq!(
            pod_snapshot(),
            pods_before,
            "a managed workload pod was restarted, replaced or deleted during the upgrade/soak"
        );
        assert_eq!(
            inventory_snapshot(),
            inventory_before,
            "status.inventory changed during the upgrade: a sync pruned or adopted a resource"
        );
        assert_eq!(
            managed_object_snapshot(),
            objects_before,
            "a managed ConfigMap/Deployment was deleted and re-created during the upgrade"
        );
        assert_eq!(
            history_lengths(),
            history_before,
            "a workload was re-deployed during the steady-state soak (history grew)"
        );
        std::thread::sleep(Duration::from_secs(2));
    }

    // --- 6. The control plane is healthy and still reconciles --------------------------------
    for index in 0..WORKLOADS {
        let name = workload_name(index);
        assert_eq!(
            sync_status(&name).as_deref(),
            Some("Synced"),
            "{name} is not Synced after the upgrade"
        );
        assert_eq!(
            health_status(&name).as_deref(),
            Some("Healthy"),
            "{name} is not Healthy after the upgrade"
        );
    }
    assert!(
        reconcile_total(new.metrics) > 0.0,
        "the rolled control plane never reported a reconcile"
    );
    assert_eq!(
        http_status(new.address, "/readyz"),
        Some(200),
        "the rolled control plane stopped reporting ready"
    );

    new.stop();
}

/// **`T20.4` acceptance:** `ferriscd backup export`/`restore` is secret-free, ordered, idempotent and
/// pre-flights its credentials.
#[test]
#[ignore = "requires a live kind cluster (make kind-up) and kubectl"]
fn a_backup_bundle_round_trips_through_a_disaster_recovery_restore() {
    // First statement: `install_current_crds` re-creates the CRDs the other live test may be
    // deleting (or replacing with the v1.0 baseline), so this is the serialisation point.
    let _live = live_suite();
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );

    let _cleanup = BackupCleanup::new();
    install_current_crds();
    create_namespace(BACKUP_NAMESPACE);
    create_namespace(BACKUP_TENANT_NAMESPACE);
    apply_stdin(&backup_fixtures());
    apply_backup_secret();
    apply_tenant_decoy_secret();

    let work = tempfile::tempdir().expect("create the bundle directory");
    let bundle = work.path().join("bundle.yaml");

    // --- 0. `H-NEW-1`: a whole-cluster export inventories the control plane's credentials only ----
    // The decoy in `BACKUP_TENANT_NAMESPACE` carries the credential label and a real-looking payload,
    // and this export is *not* namespaced — the exact scenario the review asked about. It must not
    // appear: the controller reads credentials through a namespaced `Api<Secret>` in its own
    // namespace, so a tenant `Secret` is never a dependency of a restore.
    let whole_cluster = work.path().join("whole-cluster.yaml");
    let exported = ferriscd(&[
        "backup",
        "export",
        "--control-plane-namespace",
        BACKUP_NAMESPACE,
        "--output",
        whole_cluster
            .to_str()
            .expect("utf8 whole-cluster bundle path"),
    ]);
    assert!(
        exported.status.success(),
        "a whole-cluster export failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let whole_cluster_document =
        std::fs::read_to_string(&whole_cluster).expect("the whole-cluster bundle was written");
    assert!(
        whole_cluster_document.contains(BACKUP_SECRET),
        "the control-plane credential must be inventoried:\n{whole_cluster_document}"
    );
    for absent in [BACKUP_TENANT_SECRET, BACKUP_TENANT_NAMESPACE] {
        assert!(
            !whole_cluster_document.contains(absent),
            "a labelled Secret outside the control-plane namespace is not a credential FerrisCD \
             consumes, so {absent:?} must not be inventoried:\n{whole_cluster_document}"
        );
    }

    // --- 1. Export ---------------------------------------------------------------------------
    // `--namespace` bounds the bundle for a big fleet; the control-plane namespace is where the
    // control plane's own objects *and* its credentials live (the live fixture runs one namespace).
    let exported = ferriscd(&[
        "backup",
        "export",
        "--namespace",
        BACKUP_NAMESPACE,
        "--control-plane-namespace",
        BACKUP_NAMESPACE,
        "--output",
        bundle.to_str().expect("utf8 bundle path"),
    ]);
    assert!(
        exported.status.success(),
        "backup export failed: {}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let document = std::fs::read_to_string(&bundle).expect("the bundle was written");

    assert!(
        document.contains("schemaVersion: ferriscd.io/backup/v1"),
        "the bundle must be a versioned manifest:\n{document}"
    );
    assert!(
        document.contains("sha256:"),
        "the bundle must carry an integrity digest"
    );
    // The **trap guard**: no secret material, in any shape.
    for forbidden in [
        BACKUP_SECRET_PASSWORD,
        "stringData",
        "kind: Secret",
        "resourceVersion",
        "creationTimestamp",
        "managedFields",
        "uid:",
        "status:",
        "kubectl.kubernetes.io/last-applied-configuration",
    ] {
        assert!(
            !document.contains(forbidden),
            "the bundle must not contain {forbidden:?}:\n{document}"
        );
    }
    // The same statement structurally: no resource carries a `data` map, and the only `data` key
    // names in the document are the *stub's* (`keys:`), never a value.
    let parsed: Value = serde_saphyr::from_str(&document).expect("the bundle is YAML");
    for resource in parsed["resources"]
        .as_array()
        .expect("a bundle carries resources")
    {
        assert_ne!(
            resource["kind"].as_str(),
            Some("Secret"),
            "a bundle must never carry a Secret object"
        );
        // A control-plane `ConfigMap` legitimately carries configuration; nothing else may carry a
        // `data` map, which is the shape a credential would take.
        assert!(
            resource["kind"].as_str() == Some("ConfigMap") || resource.get("data").is_none(),
            "a bundle resource must never carry a `data` map: {resource}"
        );
        assert!(
            resource["metadata"].get("uid").is_none(),
            "a bundle resource must never carry a uid: {resource}"
        );
    }
    for stub in parsed["secrets"].as_array().expect("a secret inventory") {
        for key in stub.as_object().expect("a stub is a map").keys() {
            assert!(
                matches!(key.as_str(), "namespace" | "name" | "labels" | "keys"),
                "a secret stub may only carry names, labels and key names, found {key:?}"
            );
        }
    }
    // ...while the credential it depends on is named, without its value.
    assert!(
        document.contains(BACKUP_SECRET),
        "the bundle must record the credential Secret it needs:\n{document}"
    );
    assert!(
        document.contains("ferriscd.io/secret-type"),
        "the secret stub must record the secret-type label"
    );
    assert!(
        document.contains("password"),
        "the secret stub must record the expected data key names"
    );

    // --- 2. A dry run mutates nothing ---------------------------------------------------------
    let uid_before = resource_uid("appproject", BACKUP_PROJECT);
    let dry_run = ferriscd(&[
        "backup",
        "restore",
        bundle.to_str().expect("utf8 bundle path"),
        "--dry-run",
    ]);
    assert!(
        dry_run.status.success(),
        "a dry-run restore of an unchanged control plane must succeed: {}",
        String::from_utf8_lossy(&dry_run.stderr)
    );
    assert!(
        String::from_utf8_lossy(&dry_run.stdout).contains("would apply (dry run)"),
        "a dry run must report what it would do: {}",
        String::from_utf8_lossy(&dry_run.stdout)
    );
    assert_eq!(
        resource_uid("appproject", BACKUP_PROJECT),
        uid_before,
        "a --dry-run restore must not touch the cluster"
    );

    // --- 3. Real DR: lose the control-plane objects, restore them -----------------------------
    delete_application(BACKUP_APPLICATIONS[0]);
    delete_application(BACKUP_APPLICATIONS[1]);
    delete_resource("appproject", BACKUP_PROJECT);
    assert!(application_spec(BACKUP_NAMESPACE, BACKUP_APPLICATIONS[0]).is_none());

    let restored = ferriscd(&["backup", "restore", bundle.to_str().expect("utf8 path")]);
    assert!(
        restored.status.success(),
        "backup restore failed: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    for name in BACKUP_APPLICATIONS {
        let spec = application_spec(BACKUP_NAMESPACE, name)
            .unwrap_or_else(|| panic!("{name} was not restored"));
        assert_eq!(spec["project"].as_str(), Some(BACKUP_PROJECT));
        assert_eq!(
            spec["destination"]["namespace"].as_str(),
            Some(BACKUP_NAMESPACE)
        );
    }
    assert!(resource_uid("appproject", BACKUP_PROJECT).is_some());

    // --- 4. Idempotency: a second restore changes nothing ------------------------------------
    let uids_before = BTreeMap::from([
        (
            BACKUP_PROJECT.to_owned(),
            resource_uid("appproject", BACKUP_PROJECT).expect("project uid"),
        ),
        (
            BACKUP_APPLICATIONS[0].to_owned(),
            resource_uid("application", BACKUP_APPLICATIONS[0]).expect("application uid"),
        ),
    ]);
    let generations_before = (
        resource_generation("appproject", BACKUP_PROJECT),
        resource_generation("application", BACKUP_APPLICATIONS[0]),
    );

    let again = ferriscd(&["backup", "restore", bundle.to_str().expect("utf8 path")]);
    assert!(
        again.status.success(),
        "a second restore must be idempotent: {}",
        String::from_utf8_lossy(&again.stderr)
    );
    for (name, uid) in &uids_before {
        let kind = if name == BACKUP_PROJECT {
            "appproject"
        } else {
            "application"
        };
        assert_eq!(
            resource_uid(kind, name).as_deref(),
            Some(uid.as_str()),
            "{name} was deleted and re-created by an idempotent restore"
        );
    }
    assert_eq!(
        (
            resource_generation("appproject", BACKUP_PROJECT),
            resource_generation("application", BACKUP_APPLICATIONS[0]),
        ),
        generations_before,
        "an idempotent restore must not bump metadata.generation"
    );

    // --- 5. The secret pre-flight fails closed on a missing credential -----------------------
    delete_resource("secret", BACKUP_SECRET);
    let refused = ferriscd(&["backup", "restore", bundle.to_str().expect("utf8 path")]);
    assert!(
        !refused.status.success(),
        "a restore whose credential Secret is missing must fail"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains(BACKUP_SECRET),
        "the refusal must name the missing credential: {stderr}"
    );
    assert!(
        !stderr.contains(BACKUP_SECRET_PASSWORD),
        "the refusal must never quote a secret value: {stderr}"
    );

    // ...unless the operator explicitly stages the restore first.
    let staged = ferriscd(&[
        "backup",
        "restore",
        bundle.to_str().expect("utf8 bundle path"),
        "--allow-missing-secrets",
    ]);
    assert!(
        staged.status.success(),
        "--allow-missing-secrets must let a staged restore proceed: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
}

// ---------------------------------------------------------------------------
// control-plane child processes
// ---------------------------------------------------------------------------

/// One `ferriscd server` under test, killed on every exit path.
struct ServerProcess {
    child: Child,
    address: SocketAddr,
    metrics: SocketAddr,
    identity: String,
}

impl ServerProcess {
    fn start(identity: &str) -> Self {
        let address = free_address();
        let metrics = free_address();
        // Keep the child's log: when a convergence assertion fails, the *why* is in there.
        let log_path = std::env::temp_dir().join(format!("ferriscd-e2e-{identity}.log"));
        let log = std::fs::File::create(&log_path).expect("the e2e log file is created");
        eprintln!("control plane {identity}: log at {}", log_path.display());
        let child = Command::new(env!("CARGO_BIN_EXE_ferriscd"))
            .args([
                "server",
                "--api-addr",
                &address.to_string(),
                "--metrics-addr",
                &metrics.to_string(),
                "--namespace",
                UPGRADE_NAMESPACE,
                "--allow-local-repos",
                "--auth-policy",
                "pass-through",
                "--github-webhook-secret",
                "upgrade-e2e-secret",
                "--webhook-debounce-seconds",
                "0",
            ])
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("the log file clones")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("the ferriscd binary must start");
        Self {
            child,
            address,
            metrics,
            identity: identity.to_owned(),
        }
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            eprintln!("killing the {} control plane", self.identity);
        }
        self.stop();
    }
}

/// Waits until `address` reports ready, asserting the `503` phase really happens first.
fn wait_for_ready_gated(address: SocketAddr) -> String {
    let deadline = Instant::now() + STARTUP_BUDGET;
    let mut saw_unready = false;
    while Instant::now() < deadline {
        if let Some((status, body)) = http_request(address, "/readyz") {
            if status == 200 {
                assert!(
                    saw_unready,
                    "the control plane answered 200 on the very first probe, so the readiness gate \
                     was never observed: this assertion would be vacuous"
                );
                return assert_ready_body(body);
            }
            saw_unready = true;
            assert_unready_body(status, &body);
        }
        std::thread::sleep(Duration::from_millis(if saw_unready { 100 } else { 5 }));
    }
    panic!("the control plane did not report ready within {STARTUP_BUDGET:?}");
}

/// A failing readiness probe must be `503` with the documented secret-free reason.
fn assert_unready_body(status: u16, body: &str) {
    assert_eq!(
        status, 503,
        "an unready control plane must answer 503: {body}"
    );
    assert!(
        body.contains(r#""status":"not ready""#),
        "the 503 must carry the documented not-ready payload, got: {body}"
    );
    assert!(
        body.contains("waiting for initial control-plane readiness"),
        "the 503 must name the pending gates, got: {body}"
    );
    for secret in ["token", "Bearer", "password", "kubeconfig"] {
        assert!(
            !body.contains(secret),
            "a readiness reason must never name a credential, got {secret:?} in: {body}"
        );
    }
}

/// Waits until `new` is ready, and while it is not, asserts `old` is still serving `200`.
fn wait_for_ready_gated_while_old_serves(new: SocketAddr, old: SocketAddr) -> String {
    let deadline = Instant::now() + READY_BUDGET;
    let mut saw_unready = false;
    while Instant::now() < deadline {
        if let Some((status, body)) = http_request(new, "/readyz") {
            if status == 200 {
                assert!(
                    saw_unready,
                    "the rolled control plane answered 200 on the very first probe, so its \
                     readiness gate was never observed: the zero-downtime claim would be vacuous"
                );
                return assert_ready_body(body);
            }
            saw_unready = true;
            assert_unready_body(status, &body);
            // The whole point of a readiness gate: the new instance is *not* admitted yet, so the
            // old one must still be serving — that is what makes the rollout zero-downtime.
            assert_eq!(
                http_status(old, "/readyz"),
                Some(200),
                "the new control plane is unready ({status}) while the old one is not serving: this \
                 upgrade would be disruptive"
            );
        }
        std::thread::sleep(Duration::from_millis(if saw_unready { 100 } else { 5 }));
    }
    panic!("the new control plane did not report ready within {READY_BUDGET:?}");
}

fn assert_ready_body(body: String) -> String {
    assert!(
        body.contains(r#""status":"ready""#),
        "expected the documented ready payload, got: {body}"
    );
    body
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    listener.local_addr().expect("an address")
}

/// `(status, body)` of one `GET path`, or `None` when nothing answers.
fn http_request(address: SocketAddr, path: &str) -> Option<(u16, String)> {
    let mut stream = TcpStream::connect(address).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).ok()?;
    let text = String::from_utf8_lossy(&response);
    let status = text.split_whitespace().nth(1)?.parse::<u16>().ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_owned());
    Some((status, body))
}

fn http_status(address: SocketAddr, path: &str) -> Option<u16> {
    http_request(address, path).map(|(status, _)| status)
}

/// Sums every series of `ferriscd_reconcile_total` on the process's `/metrics`.
fn reconcile_total(address: SocketAddr) -> f64 {
    let Some((200, body)) = http_request(address, "/metrics") else {
        return 0.0;
    };
    body.lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter(|line| line.starts_with("ferriscd_reconcile_total"))
        .filter_map(|line| line.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

// ---------------------------------------------------------------------------
// cleanup guards
// ---------------------------------------------------------------------------

/// Removes the upgrade fixtures on every exit path, and leaves the `v2.0` CRDs installed.
struct UpgradeCleanup;

impl UpgradeCleanup {
    fn new() -> Self {
        Self::delete_all();
        // A previous run may have panicked before re-installing the current CRDs; deleting the
        // fixtures below needs *one* of the two schemas installed, so make it deterministic.
        install_current_crds();
        Self
    }

    fn delete_all() {
        for index in 0..WORKLOADS {
            let name = workload_name(index);
            let _ = kubectl(&[
                "-n",
                UPGRADE_NAMESPACE,
                "patch",
                "application",
                &name,
                "--type=merge",
                "-p",
                r#"{"metadata":{"finalizers":null}}"#,
            ]);
            let _ = kubectl(&[
                "-n",
                UPGRADE_NAMESPACE,
                "delete",
                "application",
                &name,
                "--ignore-not-found=true",
                "--timeout=60s",
            ]);
        }
        let _ = kubectl(&[
            "-n",
            UPGRADE_NAMESPACE,
            "delete",
            "appproject",
            UPGRADE_PROJECT,
            "--ignore-not-found=true",
            "--timeout=60s",
        ]);
        for namespace in [UPGRADE_TARGET_NAMESPACE, UPGRADE_NAMESPACE] {
            let _ = kubectl(&[
                "delete",
                "namespace",
                namespace,
                "--ignore-not-found=true",
                "--timeout=180s",
            ]);
        }
    }
}

impl Drop for UpgradeCleanup {
    fn drop(&mut self) {
        Self::delete_all();
        // Never leave a `v1.0` schema behind for the next suite.
        install_current_crds();
    }
}

/// Removes the backup fixtures on every exit path.
struct BackupCleanup;

impl BackupCleanup {
    fn new() -> Self {
        Self::delete_all();
        Self
    }

    fn delete_all() {
        for name in BACKUP_APPLICATIONS {
            let _ = kubectl(&[
                "-n",
                BACKUP_NAMESPACE,
                "patch",
                "application",
                name,
                "--type=merge",
                "-p",
                r#"{"metadata":{"finalizers":null}}"#,
            ]);
            let _ = kubectl(&[
                "-n",
                BACKUP_NAMESPACE,
                "delete",
                "application",
                name,
                "--ignore-not-found=true",
                "--timeout=60s",
            ]);
        }
        let _ = kubectl(&[
            "-n",
            BACKUP_NAMESPACE,
            "delete",
            "appproject",
            BACKUP_PROJECT,
            "--ignore-not-found=true",
            "--timeout=60s",
        ]);
        let _ = kubectl(&[
            "-n",
            BACKUP_NAMESPACE,
            "delete",
            "secret",
            BACKUP_SECRET,
            "--ignore-not-found=true",
        ]);
        let _ = kubectl(&[
            "delete",
            "namespace",
            BACKUP_NAMESPACE,
            "--ignore-not-found=true",
            "--timeout=180s",
        ]);
        // The decoy tenant namespace (and its `Secret`) goes too, so a re-run starts from nothing.
        let _ = kubectl(&[
            "delete",
            "namespace",
            BACKUP_TENANT_NAMESPACE,
            "--ignore-not-found=true",
            "--timeout=180s",
        ]);
    }
}

impl Drop for BackupCleanup {
    fn drop(&mut self) {
        Self::delete_all();
    }
}

// ---------------------------------------------------------------------------
// CRD installation
// ---------------------------------------------------------------------------

/// Every FerrisCD CRD a `v2.0` cluster installs.
const FERRISCD_CRDS: [&str; 3] = [
    "applications.ferriscd.io",
    "appprojects.ferriscd.io",
    "applicationsets.ferriscd.io",
];

/// Installs the frozen `v1.0` CRDs, replacing whatever was installed.
///
/// A reinstall is what makes the baseline real: a client- or server-side apply of a *smaller* schema
/// over a `v2.0` one leaves the added properties in place, so only a delete-and-create starts from a
/// genuine `v1.0` API server state. Deleting a CRD also deletes every custom resource of that kind —
/// inherent to the API, and the reason this suite is `#[ignore]`d and documented to run on a
/// disposable `kind` cluster.
fn install_v1_0_crds() {
    reset_ferriscd_crds();
    let crds = v1_0_fixture_directory();
    for file in [
        "applications.ferriscd.io.yaml",
        "appprojects.ferriscd.io.yaml",
    ] {
        let path = crds.join(file);
        let output = kubectl(&["apply", "-f", &path.to_string_lossy()]);
        assert!(
            output.status.success(),
            "failed to install the v1.0 CRD '{}': {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    wait_for_established(&["applications.ferriscd.io", "appprojects.ferriscd.io"]);
    assert!(
        jsonpath(&[
            "get",
            "crd",
            "applications.ferriscd.io",
            "-o",
            "jsonpath={.spec.versions[0].schema.openAPIV3Schema.properties.spec.properties.sources.type}",
        ])
        .is_none(),
        "the baseline install must be the v1.0 schema, which has no spec.sources"
    );
}

/// Deletes every FerrisCD custom resource and CRD, and waits until the API server has dropped them.
///
/// Two things make this deterministic instead of racy:
///
/// * a CR whose `ferriscd.io/finalizer` was left behind by an interrupted run blocks the CRD's
///   deletion, so the finalizer is stripped first;
/// * a CRD that is still terminating *accepts* an update (so `kubectl apply` "succeeds") while every
///   create of that kind is refused, so the CRD's absence is polled for instead of assumed.
fn reset_ferriscd_crds() {
    for plural in ["applications", "applicationsets", "appprojects"] {
        let items = json_or_null(&["get", plural, "-A", "-o", "json"]);
        let Some(items) = items.get("items").and_then(Value::as_array) else {
            continue;
        };
        for item in items {
            let namespace = item["metadata"]["namespace"].as_str().unwrap_or_default();
            let name = item["metadata"]["name"].as_str().unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let _ = kubectl(&[
                "-n",
                namespace,
                "patch",
                plural,
                name,
                "--type=merge",
                "-p",
                r#"{"metadata":{"finalizers":null}}"#,
            ]);
            let output = kubectl(&[
                "-n",
                namespace,
                "delete",
                plural,
                name,
                "--ignore-not-found=true",
                "--timeout=60s",
            ]);
            assert!(
                output.status.success(),
                "failed to delete {plural}/{namespace}/{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    for crd in FERRISCD_CRDS {
        let _ = kubectl(&[
            "delete",
            "crd",
            crd,
            "--ignore-not-found=true",
            "--wait=false",
        ]);
    }
    let deadline = Instant::now() + CONVERGENCE_BUDGET;
    while Instant::now() < deadline {
        if FERRISCD_CRDS
            .iter()
            .all(|crd| !kubectl(&["get", "crd", crd]).status.success())
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("the FerrisCD CRDs did not finish terminating within {CONVERGENCE_BUDGET:?}");
}

/// Installs the committed `v2.0` CRDs with Server-Side Apply (what `helm upgrade` needs first).
fn install_current_crds() {
    let crds = workspace_root().join("deploy/crds");
    let output = kubectl(&[
        "apply",
        "--server-side",
        "--force-conflicts",
        "-f",
        &crds.to_string_lossy(),
    ]);
    assert!(
        output.status.success(),
        "failed to install the current CRDs: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // Including `applicationsets.ferriscd.io`, which a `v1.0` cluster gains with this upgrade.
    wait_for_established(&FERRISCD_CRDS);
}

fn wait_for_established(crds: &[&str]) {
    let deadline = Instant::now() + CONVERGENCE_BUDGET;
    while Instant::now() < deadline {
        let established = crds.iter().all(|crd| {
            jsonpath(&[
                "get",
                "crd",
                crd,
                "-o",
                "jsonpath={.status.conditions[?(@.type==\"Established\")].status}",
            ])
            .as_deref()
                == Some("True")
        });
        if established {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("the CRDs {crds:?} did not reach Established within {CONVERGENCE_BUDGET:?}");
}

/// The frozen `v1.0` CRD manifests, owned by the `ferriscd-crd` contract fixtures.
fn v1_0_fixture_directory() -> PathBuf {
    workspace_root().join("crates/ferriscd-crd/tests/fixtures/v1_0/crds")
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn workload_name(index: usize) -> String {
    format!("{WORKLOAD_PREFIX}{index}")
}

/// Writes ten independent plain-YAML workloads (`ConfigMap` + `Deployment` each) and commits them.
fn write_fleet_repository(repository: &Path) {
    for index in 0..WORKLOADS {
        let directory = repository.join("apps").join(workload_name(index));
        std::fs::create_dir_all(&directory).expect("create the workload directory");
        let name = workload_name(index);
        std::fs::write(
            directory.join("workload.yaml"),
            format!(
                r#"apiVersion: v1
kind: ConfigMap
metadata:
  name: {name}-settings
data:
  tag: v1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {name}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: {name}
  template:
    metadata:
      labels:
        app: {name}
    spec:
      containers:
        - name: workload
          image: registry:2
          # Documented prerequisite: `kind load docker-image registry:2` makes this work offline.
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 5000
"#
            ),
        )
        .expect("write the workload manifest");
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
            "seed ten workloads",
        ],
    );
}

fn apply_project() {
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {UPGRADE_PROJECT}
  namespace: {UPGRADE_NAMESPACE}
spec:
  description: "v2.0 zero-downtime upgrade fixture"
  sourceRepos: ["*"]
  sourceNamespaces: ["{UPGRADE_NAMESPACE}"]
  destinations:
    - cluster: in-cluster
      namespace: {UPGRADE_TARGET_NAMESPACE}
  allowedServiceAccounts: ["*"]
"#
    ));
}

/// Applies the ten `Application`s in the **`v1.0`** shape: one Git source, no `spec.sources`.
fn apply_applications(repo_url: &str) {
    let mut manifest = String::new();
    for index in 0..WORKLOADS {
        let name = workload_name(index);
        manifest.push_str(&format!(
            r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {name}
  namespace: {UPGRADE_NAMESPACE}
spec:
  project: {UPGRADE_PROJECT}
  source:
    git:
      repoURL: {repo_url}
      targetRevision: HEAD
      path: apps/{name}
    renderer:
      plainYaml:
        recursive: true
  destination:
    cluster: in-cluster
    namespace: {UPGRADE_TARGET_NAMESPACE}
  syncPolicy:
    automated: {{}}
  requeueAfterSeconds: {REQUEUE_AFTER_SECONDS}
---
"#
        ));
    }
    apply_stdin(&manifest);
}

/// The backup test's control-plane objects: one project, two applications, one credential `Secret`.
fn backup_fixtures() -> String {
    let mut manifest = format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {BACKUP_PROJECT}
  namespace: {BACKUP_NAMESPACE}
spec:
  description: "disaster-recovery fixture"
  sourceRepos: ["https://github.com/example/payments.git"]
  sourceNamespaces: ["{BACKUP_NAMESPACE}"]
  destinations:
    - cluster: in-cluster
      namespace: {BACKUP_NAMESPACE}
"#
    );
    for name in BACKUP_APPLICATIONS {
        manifest.push_str(&format!(
            r#"---
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {name}
  namespace: {BACKUP_NAMESPACE}
spec:
  project: {BACKUP_PROJECT}
  source:
    git:
      repoURL: https://github.com/example/payments.git
      targetRevision: main
      path: deploy/{name}
    renderer:
      plainYaml: {{}}
  destination:
    cluster: in-cluster
    namespace: {BACKUP_NAMESPACE}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
"#
        ));
    }
    manifest
}

/// The credential `Secret` the bundle must record a stub for — with a value that must never leak.
fn apply_backup_secret() {
    apply_stdin(&format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {BACKUP_SECRET}
  namespace: {BACKUP_NAMESPACE}
  labels:
    ferriscd.io/secret-type: repository
type: Opaque
stringData:
  url: https://github.com/example/payments.git
  username: git
  password: {BACKUP_SECRET_PASSWORD}
"#
    ));
    // The shared `ClusterCleanup`-style guard already deletes it; assert it really landed.
    assert!(
        jsonpath(&[
            "-n",
            BACKUP_NAMESPACE,
            "get",
            "secret",
            BACKUP_SECRET,
            "-o",
            "jsonpath={.metadata.name}",
        ])
        .as_deref()
            == Some(BACKUP_SECRET),
        "the credential Secret fixture was not created"
    );
}

/// A labelled `Secret` in a **tenant** namespace, indistinguishable from a credential by its labels.
///
/// `H-NEW-1`: nothing may inventory it, because FerrisCD never reads a credential from a tenant
/// namespace. Its presence is what makes the whole-cluster assertion in the DR test non-vacuous — an
/// exporter that listed every labelled `Secret` in the cluster would pick this up.
fn apply_tenant_decoy_secret() {
    apply_stdin(&format!(
        r#"apiVersion: v1
kind: Secret
metadata:
  name: {BACKUP_TENANT_SECRET}
  namespace: {BACKUP_TENANT_NAMESPACE}
  labels:
    ferriscd.io/secret-type: repository
type: Opaque
stringData:
  url: https://github.com/example/tenant-only.git
  password: {BACKUP_SECRET_PASSWORD}
"#
    ));
    assert!(
        jsonpath(&[
            "-n",
            BACKUP_TENANT_NAMESPACE,
            "get",
            "secret",
            BACKUP_TENANT_SECRET,
            "-o",
            "jsonpath={.metadata.name}",
        ])
        .as_deref()
            == Some(BACKUP_TENANT_SECRET),
        "the decoy tenant Secret was not created"
    );
}

// ---------------------------------------------------------------------------
// cluster observation
// ---------------------------------------------------------------------------

/// `(pod name, (uid, restart count, creation timestamp))` for every running workload pod.
fn pod_snapshot() -> BTreeMap<String, (String, i64, String)> {
    let pods = json_or_null(&["-n", UPGRADE_TARGET_NAMESPACE, "get", "pods", "-o", "json"]);
    let mut snapshot = BTreeMap::new();
    let Some(items) = pods.get("items").and_then(Value::as_array) else {
        return snapshot;
    };
    for pod in items {
        let name = pod["metadata"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        // Only a `Running` pod counts: a pending pod has no restart history to protect.
        if pod["status"]["phase"].as_str() != Some("Running") {
            continue;
        }
        let uid = pod["metadata"]["uid"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let created = pod["metadata"]["creationTimestamp"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let restarts = pod["status"]["containerStatuses"]
            .as_array()
            .map(|statuses| {
                statuses
                    .iter()
                    .filter_map(|status| status["restartCount"].as_i64())
                    .sum::<i64>()
            })
            .unwrap_or(0);
        snapshot.insert(name, (uid, restarts, created));
    }
    snapshot
}

fn running_pods() -> usize {
    pod_snapshot().len()
}

/// Every `Application` of the control namespace, in one list call (the soak compares snapshots
/// every couple of seconds, so a read per `Application` would be needlessly chatty).
fn applications_json() -> Value {
    json_or_null(&["-n", UPGRADE_NAMESPACE, "get", "applications", "-o", "json"])
}

/// The `Application` items of [`applications_json`].
fn application_items() -> Vec<Value> {
    applications_json()["items"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// `Application name → status.inventory`, as the version-agnostic GKNN tuples it records.
fn inventory_snapshot() -> BTreeMap<String, Vec<String>> {
    let mut snapshot = BTreeMap::new();
    for application in application_items() {
        let name = application["metadata"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let mut inventory = application["status"]["inventory"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        format!(
                            "{}/{}/{}/{}",
                            entry["group"].as_str().unwrap_or_default(),
                            entry["kind"].as_str().unwrap_or_default(),
                            entry["namespace"].as_str().unwrap_or_default(),
                            entry["name"].as_str().unwrap_or_default(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        inventory.sort();
        snapshot.insert(name, inventory);
    }
    snapshot
}

/// `(kind/name → uid)` for every object the ten Applications manage.
fn managed_object_snapshot() -> BTreeMap<String, String> {
    let mut snapshot = BTreeMap::new();
    for (resource, kind) in [("configmaps", "ConfigMap"), ("deployments", "Deployment")] {
        let objects = json_or_null(&[
            "-n",
            UPGRADE_TARGET_NAMESPACE,
            "get",
            resource,
            "-o",
            "json",
        ]);
        let Some(items) = objects.get("items").and_then(Value::as_array) else {
            continue;
        };
        for object in items {
            let Some(name) = object["metadata"]["name"].as_str() else {
                continue;
            };
            if !name.starts_with(WORKLOAD_PREFIX) {
                continue;
            }
            let uid = object["metadata"]["uid"].as_str().unwrap_or_default();
            snapshot.insert(format!("{kind}/{name}"), uid.to_owned());
        }
    }
    snapshot
}

/// `Application name → status.history length` (an apply that re-deployed would append an entry).
fn history_lengths() -> BTreeMap<String, usize> {
    let mut lengths = BTreeMap::new();
    for application in application_items() {
        let name = application["metadata"]["name"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        lengths.insert(
            name,
            application["status"]["history"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0),
        );
    }
    lengths
}

fn application_spec(namespace: &str, name: &str) -> Option<Value> {
    let application = json_or_null(&["-n", namespace, "get", "application", name, "-o", "json"]);
    application
        .get("spec")
        .cloned()
        .filter(|spec| !spec.is_null())
}

fn sync_status(name: &str) -> Option<String> {
    application_field(name, "sync")
}

fn health_status(name: &str) -> Option<String> {
    application_field(name, "health")
}

/// `status.<field>.status` of one `Application`, read as JSON (not a `jsonpath` template: the
/// template engine silently maps an unparseable expression onto "no value", which would turn a
/// broken selector into a 300-second timeout instead of an error).
fn application_field(name: &str, field: &str) -> Option<String> {
    let application = json_or_null(&[
        "-n",
        UPGRADE_NAMESPACE,
        "get",
        "application",
        name,
        "-o",
        "json",
    ]);
    application["status"][field]["status"]
        .as_str()
        .map(str::to_owned)
}

fn operation(name: &str) -> Option<String> {
    jsonpath(&[
        "-n",
        UPGRADE_NAMESPACE,
        "get",
        "application",
        name,
        "-o",
        "jsonpath={.metadata.annotations.ferriscd\\.io/operation}",
    ])
}

fn request_operation(name: &str) {
    let output = kubectl(&[
        "-n",
        UPGRADE_NAMESPACE,
        "annotate",
        "application",
        name,
        r#"ferriscd.io/operation={"sync":{}}"#,
        "--overwrite",
    ]);
    assert!(
        output.status.success(),
        "failed to queue a sync operation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn resource_uid(kind: &str, name: &str) -> Option<String> {
    jsonpath(&[
        "-n",
        BACKUP_NAMESPACE,
        "get",
        kind,
        name,
        "-o",
        "jsonpath={.metadata.uid}",
    ])
}

fn resource_generation(kind: &str, name: &str) -> Option<String> {
    jsonpath(&[
        "-n",
        BACKUP_NAMESPACE,
        "get",
        kind,
        name,
        "-o",
        "jsonpath={.metadata.generation}",
    ])
}

fn delete_application(name: &str) {
    delete_resource("application", name);
}

fn delete_resource(kind: &str, name: &str) {
    let output = kubectl(&[
        "-n",
        BACKUP_NAMESPACE,
        "delete",
        kind,
        name,
        "--ignore-not-found=true",
        "--timeout=60s",
    ]);
    assert!(
        output.status.success(),
        "failed to delete {kind}/{name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_namespace(namespace: &str) {
    let output = kubectl(&["create", "namespace", namespace]);
    assert!(
        output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("AlreadyExists"),
        "failed to create namespace {namespace}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---------------------------------------------------------------------------
// shell helpers
// ---------------------------------------------------------------------------

fn current_kube_context() -> String {
    let output = kubectl(&["config", "current-context"]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn workspace_root() -> PathBuf {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package: this file is
    // `#[path]`-included from `crates/ferriscd-cli/tests/v2_0_upgrade_soak.rs`, so `../..` is the
    // workspace root where `deploy/` lives.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root")
}

fn assert_binary(binary: &str, args: &[&str]) {
    let output = Command::new(binary)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("`{binary}` must be on PATH: {error}"));
    assert!(
        output.status.success(),
        "`{binary} {}` failed",
        args.join(" ")
    );
}

fn git(directory: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .args(args)
        .current_dir(directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Runs the `ferriscd` binary under test.
fn ferriscd(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ferriscd"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("the ferriscd binary must run")
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

/// Parses `kubectl ... -o json` output, or `null` when the object does not exist.
fn json_or_null(args: &[&str]) -> Value {
    let output = kubectl(args);
    if !output.status.success() {
        return Value::Null;
    }
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

/// Polls `condition` until it holds or `budget` elapses (a bounded retry, never a fixed sleep).
///
/// On failure it reports the observed `Application` statuses, so a timeout is a diagnosis instead of
/// a mystery.
fn wait_for(budget: Duration, what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut observed = String::new();
    for index in 0..WORKLOADS {
        let name = workload_name(index);
        let application = json_or_null(&[
            "-n",
            UPGRADE_NAMESPACE,
            "get",
            "application",
            &name,
            "-o",
            "json",
        ]);
        observed.push_str(&format!(
            "\n  {name}: sync={:?} health={:?} ready={:?} message={:?}",
            application["status"]["sync"]["status"].as_str(),
            application["status"]["health"]["status"].as_str(),
            application["status"]["conditions"][0]["reason"].as_str(),
            application["status"]["conditions"][0]["message"].as_str(),
        ));
    }
    let running = running_pods();
    panic!(
        "timed out after {budget:?} waiting for {what}; {running} of {WORKLOADS} pods are \
         running:{observed}"
    );
}

// ---------------------------------------------------------------------------
// The invariants the two `#[ignore]`d tests above depend on
// ---------------------------------------------------------------------------

// These run in `make gate` (no cluster needed). The serialisation guard is the one whose absence
// would not show up as a wrong assertion but as two live tests deleting each other's CRDs, so it is
// proven here rather than assumed.

#[test]
fn the_live_suite_guard_is_exclusive_across_threads() {
    // What the second live test hits while the first one holds the guard: it blocks instead of
    // running, whatever `--test-threads` says. `try_lock` from another thread is the non-blocking
    // proof of that (a blocking `lock` here would deadlock the test).
    let held = live_suite();
    let blocked = std::thread::spawn(|| LIVE_SUITE.try_lock().is_err())
        .join()
        .expect("the probe thread must not panic");
    assert!(
        blocked,
        "the live-suite lock must already be held by this test, otherwise the two live tests could \
         delete each other's FerrisCD CRDs"
    );
    drop(held);
    // And it is reusable once released, which is what lets the second live test run at all.
    drop(acquire(&LIVE_SUITE));
}

#[test]
fn a_poisoned_live_suite_lock_still_lets_the_other_test_run() {
    // A leaked, locally-poisoned mutex has the same shape as `LIVE_SUITE` and proves the same
    // recovery, without poisoning the real lock for the rest of the process.
    let poisoned: &'static Mutex<()> = Box::leak(Box::new(Mutex::new(())));
    let _ = std::thread::spawn(move || {
        let _guard = poisoned.lock().expect("acquired before the panic");
        panic!("intentional: the poisoning proof");
    })
    .join();
    assert!(
        poisoned.lock().is_err(),
        "the probe thread must have left the mutex poisoned"
    );
    // A live test that already panicked must not turn the other live test into a `PoisonError`
    // failure: it takes the lock, recovers, and reports its own result.
    drop(acquire(poisoned));
}

/// **Docs lint (not a behavioural test).** Guards the *prose* of this file: the module documentation
/// is the operator's instruction sheet for running the live suite, so it must describe the mechanism
/// that actually serialises the two tests (`LIVE_SUITE`) and must never prescribe a `--test-threads`
/// flag. `make test-integration` (`cargo test --workspace -- --ignored`) passes no thread-count flag,
/// so a doc that told an operator to pass one would describe an invocation nobody runs — and a reader
/// who then ran the documented command on its own would get a concurrent CRD delete.
///
/// It asserts nothing about the tests' behaviour
/// (`the_live_suite_guard_is_exclusive_across_threads` proves the lock); it only fails when the
/// file's own documentation drifts from how the suite is really run.
#[test]
fn the_module_docs_do_not_prescribe_a_test_thread_flag() {
    // Only the module documentation, never this file's own code (which necessarily contains the
    // pattern it rejects).
    let docs = include_str!("v2_0_upgrade_soak.rs")
        .lines()
        .filter(|line| line.starts_with("//!"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !docs.contains("--test-threads=1"),
        "the suite is serial by construction (LIVE_SUITE); documenting a thread-count flag would \
         hide the fact that `make test-integration` (`cargo test --workspace -- --ignored`) passes \
         none, and the two live tests would then run concurrently"
    );
    assert!(
        docs.contains("LIVE_SUITE"),
        "the module docs must name the guard that serialises the two live tests"
    );
}
