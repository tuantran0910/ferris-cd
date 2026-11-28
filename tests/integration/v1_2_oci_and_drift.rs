//! Live `v1.2` OCI-source test: a real Helm chart **and** a real Kustomize bundle are pushed to a
//! real in-cluster `registry:2`, reconciled through `spec.source.oci`, and then driven through the
//! three contract points `T18.4` adds to the live path — digest-pinned convergence, an idempotent
//! second pass, and a rollback to the prior digest — plus the `T18.2` drift watcher healing an
//! out-of-band edit of a resource that came from an **OCI** source.
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. It asserts that `kubectl config
//! current-context` begins with `kind-` before doing anything, and it is `#[ignore]`d so `cargo
//! test` never runs it. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v1_2_oci_and_drift -- --ignored --test-threads=1
//! ```
//!
//! # Prerequisites
//!
//! * a `kind` cluster from `make kind-up`;
//! * `kubectl`, `helm` (v3+) and `kustomize` (v5) on `PATH` — the renderers shell out to them, and
//!   `helm package` builds the chart artifact this test pushes;
//! * network access **or** a pre-loaded `registry:2` image on the node
//!   (`kind load docker-image registry:2 --name ferriscd-dev`). The Deployment uses
//!   `imagePullPolicy: IfNotPresent`, so a cached image is enough.
//!
//! # Why the registry is reached over `kubectl port-forward`
//!
//! The controller under test is a **host** process (`CARGO_BIN_EXE_ferriscd`), exactly as it is in
//! the other live suites, so it cannot dial a `ClusterIP`. `registry:2` therefore runs in the
//! cluster (that is the point: a real registry, not a mock) and the test forwards a free local port
//! to it. The `Application` names that forwarded endpoint, which is also why the controller is
//! started with `--allow-local-repos`: plaintext `http://` registries are refused under the
//! production policy by construction (`OciUrlPolicy::Production` + `reqwest::https_only`), and the
//! local-development opt-in is the documented, warn-logged escape hatch a `kind` demo needs.
//!
//! # What this pins (and why each assertion is not vacuous)
//!
//! 1. **The real transport ran.** `ferriscd_source_fetch_duration_seconds_count{source_kind="oci"}`
//!    is `>= 1` while `source_kind="git"` stays `0`: the live `RegistryOciClient` resolved a tag and
//!    downloaded a blob over HTTP, and the `source_kind` label is the closed enum, not a hostname.
//! 2. **Both artifact shapes work.** The Helm chart arrives with
//!    `application/vnd.cncf.helm.chart.content.v1.tar+gzip` and is rendered by `helm template`
//!    after the extractor unwrapped its single `<chart>/` root; the Kustomize bundle arrives with
//!    `application/vnd.oci.image.layer.v1.tar+gzip` (no unwrap) and is rendered by `kustomize
//!    build`.
//! 3. **Digest-pinned convergence.** `status.sync.revision` is the immutable
//!    `sha256:<64-hex>` manifest digest — never the tag — and pinning `spec.source.oci.digest`
//!    keeps the Application converged on that digest with **zero** further registry round trips
//!    (the `source_kind="oci"` observation count does not advance).
//! 4. **Idempotent second pass.** A manual `ferriscd.io/operation: {"sync":{}}` is consumed by the
//!    controller, and the resulting pass re-deploys the *same* digest with the *same* content — the
//!    Application never flaps on a second pass.
//! 5. **Rollback to the prior digest.** After the tag moves to `2.0.0`, a
//!    `{"rollback":{"id":<1.0.0>}}` request redeploys the **pinned 1.0.0 digest** (the tag still
//!    says `2.0.0`), and the documented rail applies: `spec.syncPolicy.automated` is removed so
//!    self-heal cannot fight the rollback.
//! 6. **The drift watcher covers OCI sources.** With `requeueAfterSeconds: 600` (Model 1 cannot be
//!    the cause), an out-of-band `kubectl patch` of the chart's `ConfigMap` is healed in under
//!    30 s.
//!
//! Every wait is a bounded poll of observable cluster state — never a fixed sleep — and every child
//! process (controller, port-forward) is killed on all exit paths by a `Drop` guard, so a failing
//! assertion cannot leak a process or wedge the next run.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target and never
// ships in a runtime binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Control-plane namespace this test owns: the controller watches only this one, so a stray
/// `Application` elsewhere can never be reconciled by the process under test.
const CONTROL_NAMESPACE: &str = "ferriscd-oci-e2e";
/// Namespace the fixture `Application`s deploy into (created by the test, not by the artifact, so
/// the first reconcile applies the `ConfigMap` instead of deferring it on a missing namespace).
const TARGET_NAMESPACE: &str = "ferriscd-oci-target";
/// The `AppProject` the `Application`s reference (must live in the control-plane namespace).
const PROJECT: &str = "oci";
/// `Application` whose source is the OCI **Helm chart** (tag → digest, rollback).
const CHART_APPLICATION: &str = "ledger";
/// `Application` whose source is the OCI **Kustomize bundle** (generic layer, no chart unwrap).
const BUNDLE_APPLICATION: &str = "payments";
/// Registry repository of the Helm chart.
const CHART_REPOSITORY: &str = "charts/ledger";
/// Registry repository of the Kustomize bundle.
const BUNDLE_REPOSITORY: &str = "bundles/payments";
/// `ConfigMap` the chart renders, and the key whose value identifies the deployed chart version.
const CHART_CONFIG_MAP: &str = "ledger-settings";
/// `ConfigMap` the bundle renders.
const BUNDLE_CONFIG_MAP: &str = "payments-settings";
/// The key both fixtures vary to prove *which* artifact is deployed.
const VALUE_KEY: &str = "version";
/// Layer media type `helm push` uses for a chart layer (the extractor unwraps one `<chart>/` root).
const HELM_CHART_LAYER: &str = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";
/// Layer media type of a generic OCI image layer (a Kustomize/plain-YAML bundle at the root).
const GENERIC_LAYER: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
/// Config media type `helm package`-style artifacts carry (any value is accepted by the extractor).
const HELM_CONFIG: &str = "application/vnd.cncf.helm.config.v1+json";
/// Config media type of an artifact with no structured config (the OCI "empty" descriptor).
const EMPTY_CONFIG: &str = "application/vnd.oci.empty.v1+json";
/// Manifest media type this test writes (the engine also accepts the Docker spelling).
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// `T18.2` acceptance criterion for a drift heal: well under the `600 s` requeue.
const DRIFT_SLA: Duration = Duration::from_secs(30);
/// Budget for a first convergence (image pull + tag resolve + renderer subprocess).
const STARTUP_BUDGET: Duration = Duration::from_secs(300);
/// Budget for a pass that only re-applies an already-rendered revision.
const CONVERGENCE_BUDGET: Duration = Duration::from_secs(180);
/// The CRD this suite reads back and probes the admission of (`T18.3` schema).
const APPLICATION_CRD: &str = "applications.ferriscd.io";
/// The CEL rule the installed `spec.source.oci` schema must carry — verbatim, because its exact
/// optional-field spelling (`self.?tag`) is what decides whether an explicit `null` counts as
/// "provided".
const OCI_REFERENCE_RULE: &str = "self.?tag.hasValue() || self.?digest.hasValue()";
/// The message the API server returns when that rule refuses an `Application`.
const OCI_REFERENCE_MESSAGE: &str =
    "at least one of spec.source.oci.tag or spec.source.oci.digest must be specified";

/// `T18.4`: an OCI-sourced `Application` converges on a digest, is idempotent on a second pass,
/// heals drift, and rolls back to the prior digest — against a real `registry:2` on `kind`.
#[test]
#[ignore = "requires a live kind cluster (make kind-up), helm, kustomize and a registry:2 image"]
fn an_oci_application_converges_by_digest_stays_idempotent_heals_drift_and_rolls_back() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    assert_binary("helm", &["version", "--short"]);
    assert_binary("kustomize", &["version"]);
    assert_binary("tar", &["--version"]);

    install_crds();
    let _cleanup = ClusterCleanup::new();
    create_namespaces();

    // --- 0. A real registry, and two real artifacts pushed into it ------------------------------
    let registry = RegistryFixture::start();
    let base = registry.base_url();
    let work = tempfile::tempdir().expect("create the fixture directory");

    let chart_layer = package_chart(work.path(), "1.0.0");
    let chart_v1 = push_artifact(
        &base,
        CHART_REPOSITORY,
        "1.0.0",
        HELM_CHART_LAYER,
        HELM_CONFIG,
        &chart_layer,
    );
    let chart_layer_v2 = package_chart(work.path(), "2.0.0");
    let chart_v2 = push_artifact(
        &base,
        CHART_REPOSITORY,
        "2.0.0",
        HELM_CHART_LAYER,
        HELM_CONFIG,
        &chart_layer_v2,
    );
    assert_ne!(chart_v1, chart_v2, "two chart versions must be two digests");

    let bundle_layer = package_bundle(work.path(), "1.0.0");
    let bundle_v1 = push_artifact(
        &base,
        BUNDLE_REPOSITORY,
        "1.0.0",
        GENERIC_LAYER,
        EMPTY_CONFIG,
        &bundle_layer,
    );

    apply_project(&base);
    // Only the chart Application exists for the first four steps. `ferriscd_source_fetch_*` carries
    // no `app_name` label by design (a digest would be a high-cardinality, attacker-influenced
    // series), so the "a pinned digest executes zero registry round trips" assertion below can only
    // be made while the *only* OCI source in the process is the one being pinned. The bundle
    // Application joins later.
    apply_chart_application(&base, Some("1.0.0"), None);

    let metrics = free_address();
    let mut controller = ControllerProcess::start(metrics);

    // --- 1. The chart application converges **on the digest**, not on the tag --------------------
    wait_for(
        STARTUP_BUDGET,
        "the chart Application to converge on the pushed manifest digest",
        || {
            revision(CHART_APPLICATION).as_deref() == Some(chart_v1.as_str())
                && configmap_value(CHART_CONFIG_MAP).as_deref() == Some("1.0.0")
        },
    );
    assert!(
        chart_v1.starts_with("sha256:") && chart_v1.len() == "sha256:".len() + 64,
        "status.sync.revision must record the immutable `sha256:<64-hex>` digest, got {chart_v1}"
    );
    assert!(
        !chart_v1.contains("1.0.0"),
        "the recorded revision must be the digest, never the tag the operator wrote"
    );
    assert_eq!(
        condition_status(CHART_APPLICATION, "Ready").as_deref(),
        Some("True"),
        "a digest-converged OCI Application must report Ready=True"
    );
    assert_eq!(
        sync_status(CHART_APPLICATION).as_deref(),
        Some("Synced"),
        "a freshly converged OCI Application must report Synced"
    );

    // --- 2. Pinning `spec.source.oci.digest` converges without touching the registry ------------
    //
    // The pin makes the digest authoritative (no tag resolution) *and* lets the pass be served from
    // the render cache, so the `source_kind="oci"` observation count must not advance even though a
    // full reconcile ran — `status.observedGeneration` is what proves it ran.
    let oci_fetches_before_pin = metric(
        metrics,
        "ferriscd_source_fetch_duration_seconds_count{source_kind=\"oci\"}",
    )
    .expect("the source-fetch histogram zero-instantiates an `oci` series");
    assert!(
        oci_fetches_before_pin >= 1.0,
        "the live registry transport must have been observed before the pin is asserted"
    );
    let generation = apply_chart_application(&base, Some("1.0.0"), Some(&chart_v1));
    wait_for(
        CONVERGENCE_BUDGET,
        "the digest-pinned Application to observe its new generation",
        || observed_generation(CHART_APPLICATION) == Some(generation),
    );
    assert_eq!(
        revision(CHART_APPLICATION).as_deref(),
        Some(chart_v1.as_str()),
        "a digest-pinned Application must stay on the pinned digest"
    );
    assert_eq!(
        configmap_value(CHART_CONFIG_MAP).as_deref(),
        Some("1.0.0"),
        "a digest-pinned pass must keep the rendered content"
    );
    assert_eq!(
        metric(
            metrics,
            "ferriscd_source_fetch_duration_seconds_count{source_kind=\"oci\"}"
        ),
        Some(oci_fetches_before_pin),
        "a cached digest hit must execute zero OCI registry fetches"
    );

    // --- 3. A second pass is idempotent ---------------------------------------------------------
    request_operation(CHART_APPLICATION, r#"{"sync":{}}"#);
    wait_for(
        CONVERGENCE_BUDGET,
        "the manual sync annotation to be consumed by a settled pass",
        || operation_annotation(CHART_APPLICATION).is_none(),
    );
    assert_eq!(
        revision(CHART_APPLICATION).as_deref(),
        Some(chart_v1.as_str()),
        "an idempotent second pass must re-deploy the same digest"
    );
    assert_eq!(
        configmap_value(CHART_CONFIG_MAP).as_deref(),
        Some("1.0.0"),
        "an idempotent second pass must not change the deployed content"
    );
    assert_eq!(
        sync_status(CHART_APPLICATION).as_deref(),
        Some("Synced"),
        "the Application must stay Synced across an idempotent pass"
    );
    assert_eq!(
        metric(
            metrics,
            "ferriscd_source_fetch_duration_seconds_count{source_kind=\"oci\"}"
        ),
        Some(oci_fetches_before_pin),
        "the idempotent pass is served from the render cache too: still zero registry round trips"
    );

    // --- 4. The drift watcher heals an out-of-band edit of an OCI-managed resource --------------
    //
    // Prerequisite, and the reason `T18.2`'s own suite waits for it too: the watcher derives its
    // watch set from `status.inventory` and re-plans on a `30 s` tick, so a patch issued before the
    // `ConfigMap` stream is streaming is simply not observed (a watch only sees changes after it
    // starts). Waiting on the gauge is the observable form of "the watcher is now watching".
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
        "the metadata watch must not have been refused: a 403 would park it on the fallback"
    );

    // `requeueAfterSeconds: 600` (see `apply_chart_application`) is the point: Model 1 would need
    // ten minutes to notice, so a heal inside `DRIFT_SLA` can only come from the `T18.2` watcher —
    // and that watcher has to map a `ConfigMap` back to an Application whose source is an OCI
    // artifact (`ferriscd.io/app-hash`), which no Git-only test can prove.
    patch_configmap_out_of_band(CHART_CONFIG_MAP);
    assert_eq!(
        configmap_value(CHART_CONFIG_MAP).as_deref(),
        Some("drifted"),
        "the out-of-band patch must be visible before waiting for the heal"
    );
    let drift_start = Instant::now();
    wait_for(
        DRIFT_SLA,
        "the drifted OCI-managed ConfigMap to be healed",
        || configmap_value(CHART_CONFIG_MAP).as_deref() == Some("1.0.0"),
    );
    println!(
        "T18.4: out-of-band edit of an OCI-managed ConfigMap healed in {:?} (requeueAfterSeconds is \
         600)",
        drift_start.elapsed()
    );

    // --- 5. The Kustomize bundle converges too (generic layer, no chart unwrap) -----------------
    apply_bundle_application(&base, "1.0.0");
    wait_for(
        STARTUP_BUDGET,
        "the bundle Application to converge on the pushed bundle digest",
        || {
            revision(BUNDLE_APPLICATION).as_deref() == Some(bundle_v1.as_str())
                && configmap_value(BUNDLE_CONFIG_MAP).as_deref() == Some("1.0.0")
        },
    );

    // --- 6. The live registry transport ran, and its label is the closed enum --------------------
    wait_for(STARTUP_BUDGET, "an observed OCI source fetch", || {
        metric(
            metrics,
            "ferriscd_source_fetch_duration_seconds_count{source_kind=\"oci\"}",
        ) >= Some(2.0)
    });
    assert_eq!(
        metric(
            metrics,
            "ferriscd_source_fetch_duration_seconds_count{source_kind=\"git\"}"
        ),
        Some(0.0),
        "no Git fetch may be recorded for two OCI Applications (the label must be per source kind)"
    );

    // --- 7. The tag moves, and the Application follows it to a new digest ----------------------
    let generation = apply_chart_application(&base, Some("2.0.0"), None);
    wait_for(
        STARTUP_BUDGET,
        "the chart Application to converge on the 2.0.0 digest",
        || {
            observed_generation(CHART_APPLICATION) == Some(generation)
                && revision(CHART_APPLICATION).as_deref() == Some(chart_v2.as_str())
                && configmap_value(CHART_CONFIG_MAP).as_deref() == Some("2.0.0")
        },
    );

    // --- 8. Rollback redeploys the **prior digest**, not the tag ---------------------------------
    let history = history_id_for(CHART_APPLICATION, &chart_v1)
        .expect("the 1.0.0 deployment must be one of the 20 recorded history entries");
    request_operation(
        CHART_APPLICATION,
        &format!(r#"{{"rollback":{{"id":{history}}}}}"#),
    );
    wait_for(
        CONVERGENCE_BUDGET,
        "the rollback to redeploy the prior 1.0.0 digest",
        || {
            operation_annotation(CHART_APPLICATION).is_none()
                && revision(CHART_APPLICATION).as_deref() == Some(chart_v1.as_str())
                && configmap_value(CHART_CONFIG_MAP).as_deref() == Some("1.0.0")
        },
    );
    // The documented rail: a rollback disables automation so self-heal cannot overwrite the pin
    // with whatever the tag says next (the classic rollback-vs-`selfHeal` fight loop).
    assert!(
        application_json(CHART_APPLICATION)["spec"]["syncPolicy"]["automated"].is_null(),
        "a rollback must remove spec.syncPolicy.automated so it cannot be healed away"
    );

    controller.stop();
}

// ---------------------------------------------------------------------------
// Controller child process
// ---------------------------------------------------------------------------

/// The controller under test, killed on every exit path.
struct ControllerProcess {
    child: Child,
}

impl ControllerProcess {
    /// Starts `ferriscd controller` with the flags this test needs.
    ///
    /// `--allow-local-repos` is what makes a plaintext `http://127.0.0.1:<port>` registry
    /// admissible at all (`OciUrlPolicy::AllowLocal`); `--enable-drift-watcher` with a `ConfigMap`
    /// allow-list is the `T18.2` watcher step 4 depends on.
    fn start(metrics: SocketAddr) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ferriscd"))
            .args([
                "controller",
                "--namespace",
                CONTROL_NAMESPACE,
                "--allow-local-repos",
                "--metrics-addr",
                &metrics.to_string(),
                "--enable-drift-watcher",
                "--drift-watcher-kinds",
                "ConfigMap",
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
// Registry fixture: in-cluster `registry:2`, forwarded to a free local port
// ---------------------------------------------------------------------------

/// A `registry:2` Deployment in the control namespace, reachable from the host over
/// `kubectl port-forward`.
struct RegistryFixture {
    forward: Child,
    base: String,
}

impl RegistryFixture {
    const MANIFEST: &'static str = r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: registry
  namespace: __NAMESPACE__
spec:
  replicas: 1
  selector:
    matchLabels:
      app: registry
  template:
    metadata:
      labels:
        app: registry
    spec:
      containers:
        - name: registry
          image: registry:2
          # The image is a documented prerequisite: `kind load docker-image registry:2` makes this
          # work offline, and pulling it is the only network access this test needs.
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 5000
          readinessProbe:
            httpGet:
              path: /v2/
              port: 5000
          env:
            - name: REGISTRY_STORAGE_DELETE_ENABLED
              value: "true"
---
apiVersion: v1
kind: Service
metadata:
  name: registry
  namespace: __NAMESPACE__
spec:
  selector:
    app: registry
  ports:
    - port: 5000
      targetPort: 5000
"#;

    /// Applies the registry, waits for the rollout, forwards a free port and proves `/v2/` answers.
    fn start() -> Self {
        apply_stdin(&Self::MANIFEST.replace("__NAMESPACE__", CONTROL_NAMESPACE));
        // `kubectl rollout status` is a bounded wait (and it fails loudly), not a sleep.
        let output = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "rollout",
            "status",
            "deployment/registry",
            "--timeout=240s",
        ]);
        assert!(
            output.status.success(),
            "registry:2 did not roll out (is the image pullable, or pre-loaded with `kind load \
             docker-image registry:2`?): {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let port = free_port();
        let forward = Command::new("kubectl")
            .args([
                "-n",
                CONTROL_NAMESPACE,
                "port-forward",
                "service/registry",
                &format!("{port}:5000"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("kubectl port-forward must start");

        let fixture = Self {
            forward,
            base: format!("http://127.0.0.1:{port}"),
        };
        let port = fixture.port();
        wait_for(STARTUP_BUDGET, "the registry to answer /v2/", || {
            http_status(port, "/v2/") == Some(200)
        });
        fixture
    }

    fn base_url(&self) -> String {
        self.base.clone()
    }

    fn port(&self) -> u16 {
        self.base
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .expect("the base URL carries the forwarded port")
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        let _ = self.forward.kill();
        let _ = self.forward.wait();
    }
}

// ---------------------------------------------------------------------------
// Artifacts: `helm package`, a tar bundle, and the registry v2 push
// ---------------------------------------------------------------------------

/// Packages the `ledger` Helm chart at `version` and returns the `.tgz` bytes.
///
/// A real `helm package` (not a hand-rolled tar) matters: the extractor's single-root unwrap exists
/// precisely because `helm package` wraps the chart in `<name>/`, so the fixture has to be produced
/// the way a chart is produced.
fn package_chart(work: &Path, version: &str) -> Vec<u8> {
    let chart = work.join(format!("chart-{version}")).join("ledger");
    std::fs::create_dir_all(chart.join("templates")).expect("create the chart directory");
    std::fs::write(
        chart.join("Chart.yaml"),
        format!("apiVersion: v2\nname: ledger\nversion: {version}\n"),
    )
    .expect("write Chart.yaml");
    std::fs::write(
        chart.join("values.yaml"),
        format!("version: \"{version}\"\n"),
    )
    .expect("write values.yaml");
    std::fs::write(
        chart.join("templates/configmap.yaml"),
        format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {CHART_CONFIG_MAP}\ndata:\n  \
             {VALUE_KEY}: {{{{ .Values.version | quote }}}}\n"
        ),
    )
    .expect("write the chart template");

    let out = work.join(format!("chart-{version}-out"));
    std::fs::create_dir_all(&out).expect("create the chart output directory");
    let output = Command::new("helm")
        .arg("package")
        .arg(&chart)
        .arg("-d")
        .arg(&out)
        .output()
        .expect("helm must run");
    assert!(
        output.status.success(),
        "helm package failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    std::fs::read(out.join(format!("ledger-{version}.tgz"))).expect("the packaged chart must exist")
}

/// Builds the Kustomize bundle tar (a `kustomization.yaml` plus one `ConfigMap`) and gzips it.
///
/// The files sit at the archive root with the **generic** layer media type, which is what an
/// ORAS/Flux bundle looks like — so the extractor must *not* unwrap a directory here.
fn package_bundle(work: &Path, version: &str) -> Vec<u8> {
    let bundle = work.join(format!("bundle-{version}"));
    std::fs::create_dir_all(&bundle).expect("create the bundle directory");
    std::fs::write(
        bundle.join("kustomization.yaml"),
        "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - \
         configmap.yaml\n",
    )
    .expect("write kustomization.yaml");
    std::fs::write(
        bundle.join("configmap.yaml"),
        format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {BUNDLE_CONFIG_MAP}\ndata:\n  \
             {VALUE_KEY}: \"{version}\"\n"
        ),
    )
    .expect("write the bundle ConfigMap");

    let archive = work.join(format!("bundle-{version}.tgz"));
    // `--format=ustar` is load-bearing: macOS `bsdtar` defaults to PAX, which writes a
    // `PaxHeader/<name>` extended-header entry (and AppleDouble `._<name>` files when the files
    // carry xattrs). The extractor accepts **only** plain files and directories by design, so it
    // rejects those — correctly — and the whole point of this fixture is the generic layer path, not
    // a tar-format argument. `ustar` is also what `helm package` (Go's `archive/tar`) emits.
    let output = Command::new("tar")
        .arg("--format=ustar")
        .arg("-C")
        .arg(&bundle)
        .arg("-czf")
        .arg(&archive)
        .args(["configmap.yaml", "kustomization.yaml"])
        .output()
        .expect("tar must run");
    assert!(
        output.status.success(),
        "tar failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(&archive).expect("the bundle archive must exist")
}

/// Pushes `layer` as one OCI artifact under `<base>/v2/<repository>/manifests/<tag>` and returns the
/// manifest digest the registry canonicalized it to.
///
/// The distribution upload dance is written out instead of shelling out to `oras`/`crane`/`helm
/// push` so the test has no client besides `reqwest` (already a dependency) and no tool-version
/// sensitivity: `POST .../blobs/uploads/`, `PUT <location>&digest=…`, then `PUT .../manifests/<tag>`.
/// The digest a manifest is addressed by is what the registry reports in `Docker-Content-Digest`,
/// which is exactly what the controller stores in `status.sync.revision`.
fn push_artifact(
    base: &str,
    repository: &str,
    tag: &str,
    layer_media_type: &str,
    config_media_type: &str,
    layer: &[u8],
) -> String {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime for the registry client");
    // Two crypto providers are linked in this workspace, so `rustls` refuses to guess; the
    // controller pins `ring` and so does this test (it never dials TLS, but the client is built the
    // same way).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .expect("the registry HTTP client");

    runtime.block_on(async {
        let config = b"{}".to_vec();
        let config_digest = upload_blob(&http, base, repository, config.clone()).await;
        let layer_digest = upload_blob(&http, base, repository, layer.to_vec()).await;
        let manifest = format!(
            concat!(
                r#"{{"schemaVersion":2,"mediaType":"{manifest}","#,
                r#""config":{{"mediaType":"{config_media_type}","digest":"{config_digest}","#,
                r#""size":{config_size}}},"#,
                r#""layers":[{{"mediaType":"{layer_media_type}","digest":"{layer_digest}","#,
                r#""size":{layer_size}}}]}}"#
            ),
            manifest = OCI_MANIFEST,
            config_media_type = config_media_type,
            config_digest = config_digest,
            config_size = config.len(),
            layer_media_type = layer_media_type,
            layer_digest = layer_digest,
            layer_size = layer.len(),
        );
        let response = http
            .put(format!("{base}/v2/{repository}/manifests/{tag}"))
            .header("content-type", OCI_MANIFEST)
            .body(manifest)
            .send()
            .await
            .expect("the manifest PUT must reach the registry");
        assert_eq!(
            response.status().as_u16(),
            201,
            "the registry refused the {repository}:{tag} manifest: {:?}",
            response.text().await
        );
        header_digest(&response, repository, tag)
    })
}

/// Uploads one blob and returns the digest the registry assigned it.
async fn upload_blob(
    http: &reqwest::Client,
    base: &str,
    repository: &str,
    body: Vec<u8>,
) -> String {
    let digest = format!("sha256:{}", sha256_hex(&body));
    let location = {
        let response = http
            .post(format!("{base}/v2/{repository}/blobs/uploads/"))
            .header("content-length", "0")
            .body(Vec::new())
            .send()
            .await
            .expect("the blob upload POST must reach the registry");
        assert_eq!(
            response.status().as_u16(),
            202,
            "the registry refused a {repository} blob upload session"
        );
        response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .expect("an accepted upload carries a Location header")
            .to_owned()
    };
    // `registry:2` answers with an absolute `Location` that already carries `?_state=…`, so the
    // digest is appended with the right separator instead of assuming there is no query string.
    let separator = if location.contains('?') { '&' } else { '?' };
    let url = if location.starts_with("http") {
        format!("{location}{separator}digest={digest}")
    } else {
        format!("{base}{location}{separator}digest={digest}")
    };
    let response = http
        .put(url)
        .header("content-type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .expect("the blob PUT must reach the registry");
    assert_eq!(
        response.status().as_u16(),
        201,
        "the registry refused the {digest} blob"
    );
    let assigned = header_digest(&response, repository, &digest);
    assert_eq!(
        assigned, digest,
        "the registry and this test disagree on the blob digest — the bytes it received are not \
         the bytes that were hashed"
    );
    digest
}

/// The `Docker-Content-Digest` a registry reports for a stored manifest/blob.
fn header_digest(response: &reqwest::Response, repository: &str, reference: &str) -> String {
    response
        .headers()
        .get("docker-content-digest")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("the registry reported no digest for {repository}:{reference}"))
        .to_owned()
}

/// Lowercase-hex SHA-256 of `body`.
fn sha256_hex(body: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(body);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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
        for application in [CHART_APPLICATION, BUNDLE_APPLICATION] {
            let _ = kubectl(&[
                "-n",
                CONTROL_NAMESPACE,
                "patch",
                "application",
                application,
                "--type=merge",
                "-p",
                r#"{"metadata":{"finalizers":[]}}"#,
            ]);
            let _ = kubectl(&[
                "-n",
                CONTROL_NAMESPACE,
                "delete",
                "application",
                application,
                "--ignore-not-found=true",
                "--timeout=30s",
            ]);
        }
        for namespace in [TARGET_NAMESPACE, CONTROL_NAMESPACE] {
            let _ = kubectl(&[
                "delete",
                "namespace",
                namespace,
                "--ignore-not-found=true",
                // Blocking delete: a namespace left `Terminating` by an earlier run races the next
                // create with `AlreadyExists`.
                "--timeout=180s",
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

/// Fails early (and legibly) when a shell-out prerequisite is missing.
///
/// The version flags differ per tool, so the caller passes them: `helm version` (v4 dropped
/// `--version`), `kustomize version`, and `tar --version`.
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

/// Installs the committed CRDs, then proves the **installed** schema is the revision this suite was
/// written against — and that its CEL rule really rejects the payload it is meant to reject.
///
/// Three checks, each of which a model test cannot make:
///
/// 1. `kubectl wait --for=condition=Established`: an `Application` cannot be admitted at all before
///    the API server has established the CRD, so everything below would race it.
/// 2. Read the **installed** CRD back and assert `spec.source.oci` — and its CEL rule — are there.
///    `make test-integration-twice` runs against a cluster that already has the CRDs, so a CRD left
///    by an earlier revision (one without `oci`, or with a weaker rule) would otherwise be used
///    silently and every assertion in this file would be testing the old contract.
/// 3. Evaluate the rule through the API server: `self.?tag.hasValue() || self.?digest.hasValue()`
///    must treat an explicit `null` as "not provided". The engine's own tests pin the *schema*, but
///    only a real API server says how CEL evaluates `.?` on an explicit null — and if it said
///    "provided", an OCI source with neither a tag nor a digest would be admitted and then fail at
///    reconcile time.
fn install_crds() {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package: this file is
    // `#[path]`-included from `crates/ferriscd-cli/tests/v1_2_oci_and_drift.rs`, so `../..` is the
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

    let established = kubectl(&[
        "wait",
        "--for=condition=Established",
        &format!("crd/{APPLICATION_CRD}"),
        "--timeout=120s",
    ]);
    assert!(
        established.status.success(),
        "the {APPLICATION_CRD} CRD was not established: {}",
        String::from_utf8_lossy(&established.stderr)
    );

    assert_installed_oci_schema();
    assert_oci_reference_is_enforced_by_admission();
}

fn assert_installed_oci_schema() {
    let output = kubectl(&["get", "crd", APPLICATION_CRD, "-o", "json"]);
    assert!(
        output.status.success(),
        "could not read back crd/{APPLICATION_CRD}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let crd: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("crd/{APPLICATION_CRD} is not JSON: {error}"));
    let version = &crd["spec"]["versions"][0];
    let source =
        &version["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["source"];
    let oci = &source["properties"]["oci"];
    assert!(
        oci.is_object(),
        "the installed {APPLICATION_CRD} CRD has no `spec.source.oci`: a stale (or downgraded) CRD \
         is installed on this cluster. Re-apply `deploy/crds/applications.ferriscd.io.yaml` (and \
         delete the CRD first if a `kubectl apply` was refused) before running this suite. Installed \
         source properties: {:?}",
        source["properties"]
            .as_object()
            .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
    );
    for field in ["url", "tag", "digest", "path"] {
        assert!(
            oci["properties"][field].is_object(),
            "the installed `spec.source.oci` schema is missing `{field}`: {oci}"
        );
    }
    let rules = oci["x-kubernetes-validations"]
        .as_array()
        .unwrap_or_else(|| {
            panic!("the installed `spec.source.oci` schema carries no CEL rules: {oci}")
        });
    assert!(
        rules.iter().any(|rule| {
            rule["rule"].as_str() == Some(OCI_REFERENCE_RULE)
                && rule["message"].as_str() == Some(OCI_REFERENCE_MESSAGE)
        }),
        "the installed CRD does not carry the `T18.3` rule `{OCI_REFERENCE_RULE}` with its \
         documented message; installed rules: {rules:?}"
    );
}

/// Proves the installed CEL rule with a real API-server admission decision.
///
/// `--dry-run=server` runs the full schema + CEL validation without persisting anything, and the
/// probe lives in the `default` namespace so it needs no fixture of its own.
fn assert_oci_reference_is_enforced_by_admission() {
    let probe = |reference: &str| {
        format!(
            r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: oci-admission-probe
  namespace: default
spec:
  project: default
  source:
    oci:
      url: oci://ghcr.io/example/probe
{reference}  destination:
    namespace: default
"#
        )
    };

    // Positive control: an OCI source *with* a tag is admitted, so the refusal below cannot be an
    // unrelated schema complaint (a missing field, an unparsable object, an unestablished CRD).
    let admitted = apply_dry_run(&probe("      tag: \"1.0.0\"\n"));
    assert!(
        admitted.status.success(),
        "an OCI source with a tag must be admitted by the installed CRD; got: {}",
        String::from_utf8_lossy(&admitted.stderr)
    );

    // The negative case, and the reason this cannot be a model test: an explicit `null` tag *and*
    // `null` digest must be treated as "not provided" by the API server's CEL evaluation.
    let rejected = apply_dry_run(&probe("      tag: null\n      digest: null\n"));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        !rejected.status.success(),
        "the API server admitted an OCI source with `tag: null` and `digest: null`: the installed \
         CRD's CEL `.?…hasValue()` semantics do not match the model, so an unusable source would \
         reach the controller"
    );
    assert!(
        stderr.contains(OCI_REFERENCE_MESSAGE),
        "the admission must fail with the CEL rule's message `{OCI_REFERENCE_MESSAGE}`; got: \
         {stderr}"
    );
}

/// Applies `manifest` with `--dry-run=server`, returning the raw `kubectl` result.
fn apply_dry_run(manifest: &str) -> Output {
    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-", "--dry-run=server"])
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
        .expect("the dry-run manifest is written");
    child.wait_with_output().expect("kubectl output")
}

fn create_namespaces() {
    for namespace in [CONTROL_NAMESPACE, TARGET_NAMESPACE] {
        apply_stdin(&format!(
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {namespace}\n"
        ));
    }
}

/// The `AppProject` the two `Application`s reference.
///
/// `sourceRepos` lists the **exact** forwarded registry URLs, not `*`: the `T18.4` trap guard wants
/// `AppProjectPolicy::check_application` to run against `spec.source.oci.url` *before* any registry
/// call, and a wildcard would let this test pass with a policy that never looked at the OCI URL.
fn apply_project(base: &str) {
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {PROJECT}
  namespace: {CONTROL_NAMESPACE}
spec:
  description: "OCI artifact e2e (T18.4)"
  sourceRepos:
    - {base}/{CHART_REPOSITORY}
    - {base}/{BUNDLE_REPOSITORY}
  sourceNamespaces:
    - {CONTROL_NAMESPACE}
  destinations:
    - cluster: in-cluster
      namespace: "*"
  allowedServiceAccounts: []
  clusterResourceWhitelist: []
  namespaceResourceWhitelist:
    - group: "*"
      kind: "*"
"#
    ));
}

/// Applies the chart `Application` and returns its `metadata.generation`.
///
/// `requeueAfterSeconds: 600` is deliberate: with Model 1 ten minutes away, every state this test
/// observes has to come from a spec change, a manual operation, or the drift watcher — never from a
/// periodic resync that could mask a missing trigger.
///
/// `takeoverFieldManagers` lists `kubectl-patch` because step 4 mutates the rendered `ConfigMap` as
/// that field manager. FerrisCD never forces fields owned by another manager (`serverSideForce`
/// stays `false`), so without this opt-in self-heal would correctly refuse and step 4 would time
/// out — the refusal is the safe default, this field is the documented escape hatch.
fn apply_chart_application(base: &str, tag: Option<&str>, digest: Option<&str>) -> i64 {
    let reference = match (tag, digest) {
        (Some(tag), Some(digest)) => format!("      tag: {tag}\n      digest: {digest}\n"),
        (Some(tag), None) => format!("      tag: {tag}\n"),
        (None, Some(digest)) => format!("      digest: {digest}\n"),
        (None, None) => panic!("an OCI source needs a tag or a digest"),
    };
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {CHART_APPLICATION}
  namespace: {CONTROL_NAMESPACE}
spec:
  project: {PROJECT}
  source:
    oci:
      url: {base}/{CHART_REPOSITORY}
{reference}      path: ""
    # `helm` is an empty object: the renderer enum is spelled as a single-key map, not a string.
    renderer:
      helm: {{}}
  destination:
    cluster: in-cluster
    namespace: {TARGET_NAMESPACE}
  syncPolicy:
    syncOptions:
      takeoverFieldManagers:
        - kubectl-patch
    automated:
      prune: false
      selfHeal: true
  requeueAfterSeconds: 600
"#
    ));
    generation(CHART_APPLICATION)
}

/// Applies the bundle `Application` (a Kustomize bundle at the artifact root).
fn apply_bundle_application(base: &str, tag: &str) {
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {BUNDLE_APPLICATION}
  namespace: {CONTROL_NAMESPACE}
spec:
  project: {PROJECT}
  source:
    oci:
      url: {base}/{BUNDLE_REPOSITORY}
      tag: {tag}
      path: ""
    # `kustomize` is an empty object: the renderer enum is spelled as a single-key map, not a string.
    renderer:
      kustomize: {{}}
  destination:
    cluster: in-cluster
    namespace: {TARGET_NAMESPACE}
  syncPolicy:
    syncOptions:
      takeoverFieldManagers:
        - kubectl-patch
    automated:
      prune: false
      selfHeal: true
  requeueAfterSeconds: 600
"#
    ));
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

fn application_json(name: &str) -> Value {
    let output = kubectl(&[
        "-n",
        CONTROL_NAMESPACE,
        "get",
        "application",
        name,
        "-o",
        "json",
    ]);
    serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

fn status_jsonpath(name: &str, template: &str) -> Option<String> {
    jsonpath(&[
        "-n",
        CONTROL_NAMESPACE,
        "get",
        "application",
        name,
        "-o",
        &format!("jsonpath={template}"),
    ])
}

/// `status.sync.revision` — the digest the last pass deployed.
fn revision(name: &str) -> Option<String> {
    status_jsonpath(name, "{.status.sync.revision}")
}

fn sync_status(name: &str) -> Option<String> {
    status_jsonpath(name, "{.status.sync.status}")
}

fn generation(name: &str) -> i64 {
    status_jsonpath(name, "{.metadata.generation}")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn observed_generation(name: &str) -> Option<i64> {
    status_jsonpath(name, "{.status.observedGeneration}").and_then(|value| value.parse().ok())
}

fn condition_status(name: &str, condition: &str) -> Option<String> {
    status_jsonpath(
        name,
        &format!("{{.status.conditions[?(@.type==\"{condition}\")].status}}"),
    )
}

/// The `id` of the newest `status.history` entry whose `revision` is `revision`.
fn history_id_for(name: &str, revision: &str) -> Option<i64> {
    application_json(name)["status"]["history"]
        .as_array()?
        .iter()
        .rev()
        .find(|entry| entry["revision"].as_str() == Some(revision))
        .and_then(|entry| entry["id"].as_i64())
}

fn operation_annotation(name: &str) -> Option<String> {
    status_jsonpath(name, "{.metadata.annotations.ferriscd\\.io/operation}")
}

/// Writes `ferriscd.io/operation` the way an operator or the API server would.
fn request_operation(name: &str, value: &str) {
    let output = kubectl(&[
        "-n",
        CONTROL_NAMESPACE,
        "annotate",
        "application",
        name,
        "--overwrite",
        &format!("ferriscd.io/operation={value}"),
    ]);
    assert!(
        output.status.success(),
        "kubectl annotate failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn configmap_value(name: &str) -> Option<String> {
    jsonpath(&[
        "-n",
        TARGET_NAMESPACE,
        "get",
        "configmap",
        name,
        "-o",
        &format!("jsonpath={{.data.{VALUE_KEY}}}"),
    ])
}

/// Edits a managed `ConfigMap` out of band, as field manager `kubectl-patch`.
fn patch_configmap_out_of_band(name: &str) {
    let output = kubectl(&[
        "-n",
        TARGET_NAMESPACE,
        "patch",
        "configmap",
        name,
        "--type=merge",
        "-p",
        r#"{"data":{"version":"drifted"}}"#,
    ]);
    assert!(
        output.status.success(),
        "kubectl patch failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    listener.local_addr().expect("an address").port()
}

fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");
    listener.local_addr().expect("an address")
}

/// The status code of one `GET path` against `127.0.0.1:port`, or `None` if nothing answers.
fn http_status(port: u16, path: &str) -> Option<u16> {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut line = String::new();
    std::io::BufReader::new(stream).read_line(&mut line).ok()?;
    line.split_whitespace().nth(1)?.parse().ok()
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
        let Ok(parsed) = value.parse::<f64>() else {
            continue;
        };
        total = Some(total.unwrap_or(0.0) + parsed);
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
    std::io::Read::read_to_end(&mut stream, &mut response).ok()?;
    let text = String::from_utf8_lossy(&response);
    if text.split_whitespace().nth(1)? != "200" {
        return None;
    }
    text.split_once("\r\n\r\n").map(|(_, body)| body.to_owned())
}

/// Polls `condition` until it holds or `budget` elapses.
///
/// A bounded retry loop, never a fixed sleep: it fails loudly with the observed `status` of both
/// Applications instead of hanging, and it returns as soon as the cluster agrees.
fn wait_for(budget: Duration, what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for {what}; {CHART_APPLICATION} generation {} \
             spec was: {}, status was: {}, {BUNDLE_APPLICATION} status was: {}",
            generation(CHART_APPLICATION),
            application_json(CHART_APPLICATION)["spec"],
            application_json(CHART_APPLICATION)["status"],
            application_json(BUNDLE_APPLICATION)["status"],
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
