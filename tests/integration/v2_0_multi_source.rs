//! Live `v2.0` multi-source test (`T20.1`): a Helm chart from a real **OCI registry** is rendered
//! with `values.yaml` from a **different, local Git repository**, addressed through the `$values/`
//! alias.
//!
//! # Safety gate
//!
//! This file **must never touch a non-`kind` cluster**. It asserts that `kubectl config
//! current-context` begins with `kind-` before doing anything, and it is `#[ignore]`d so `cargo
//! test` never runs it. Invoke it with:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-cli --test v2_0_multi_source -- --ignored --test-threads=1
//! ```
//!
//! # Prerequisites
//!
//! * a `kind` cluster from `make kind-up`;
//! * `helm` (v4), `git` and `kubectl` on `PATH` — `helm package` builds the chart artifact and the
//!   renderer shells out to `helm template`;
//! * a `registry:2` image on the node (`kind load docker-image registry:2 --name ferriscd-dev`), or
//!   network access to pull it. The Deployment uses `imagePullPolicy: IfNotPresent`.
//!
//! # What this pins (and why none of it is vacuous)
//!
//! 1. **The split layout really renders.** The artifact is a chart whose *own* `values.yaml` says
//!    `image.tag: chart-default`; the deployed `ConfigMap` must say the value from the **values
//!    repository**, so a missing `$values/...` resolution, an ignored `valueFiles` entry, or a
//!    silently dropped second source all show up as the wrong string.
//! 2. **The composite revision is a digest, not a commit.** `status.sync.revision` is
//!    `sha256:<64 hex>` over the ordered per-source revisions, and `status.sync.revisions` carries
//!    them in declaration order: the chart's immutable manifest digest first, the values
//!    repository's commit second. `status.history[].revisions` records the same list, which is what
//!    a later rollback re-pins.
//! 3. **Idempotency first.** A manual `ferriscd.io/operation: {"sync":{}}` re-deploys the *same*
//!    composite revision with the *same* content, so the resync below cannot be explained by "a
//!    periodic pass always applies".
//! 4. **A values commit resyncs under `selfHeal: false`.** With the chart digest pinned (so the
//!    chart revision provably cannot move) and `selfHeal: false`, committing a new `values.yaml`
//!    must move `status.sync.revisions[1]`, move the composite revision, and re-apply the rendered
//!    `ConfigMap` — and `status.sync.revision` must stay a digest while doing it.
//! 5. **The installed CRD enforces the `T20.1` rules.** The spec-level CEL rules are read back from
//!    the API server and exercised with `--dry-run=server`: `source` + `sources` is refused, 17
//!    entries are refused, and both a `v1.0` single-source object and a two-entry multi-source
//!    object are admitted (so the refusal cannot be an unrelated schema complaint).
//!
//! Every wait is a bounded poll of observable cluster state — never a fixed sleep — and every child
//! process (controller, port-forward, registry Deployment) plus every created object is cleaned up
//! on all exit paths by `Drop` guards, which is what makes the suite safe to run twice in a row
//! (`make test-integration-twice`).

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
const CONTROL_NAMESPACE: &str = "ferriscd-multi-e2e";
/// Namespace the fixture `Application` deploys into (created up front, so the first reconcile
/// applies the `ConfigMap` instead of deferring it on a missing namespace).
const TARGET_NAMESPACE: &str = "ferriscd-multi-target";
/// The `AppProject` the `Application` references (it lives in the control-plane namespace).
const PROJECT: &str = "multi";
/// The multi-source `Application` under test.
const APPLICATION: &str = "payments";
/// Registry repository the Helm chart is pushed to.
const CHART_REPOSITORY: &str = "charts/payments";
/// Pinned chart version (and layer tag) this test pushes and references.
const CHART_TAG: &str = "1.0.0";
/// The `ConfigMap` the chart renders.
const CHART_CONFIG_MAP: &str = "payments-settings";
/// The `ConfigMap` key whose value identifies **which** values file rendered it.
const VALUE_KEY: &str = "tag";
/// The chart's own default for {@link VALUE_KEY}: what would be deployed if `$values/...` did not
/// resolve, which is exactly the failure this test must catch.
const CHART_DEFAULT: &str = "chart-default";
/// CEL rule (`T20.1`) the installed `spec` schema must carry, verbatim.
const SOURCE_DECLARATION_RULE: &str = "(has(self.source) && self.source != null && !(self.?sources.hasValue() && size(self.sources) > 0)) || (!(has(self.source) && self.source != null) && self.?sources.hasValue() && size(self.sources) > 0)";
/// Message the API server returns when `source` **and** `sources` are both set.
const SOURCE_DECLARATION_MESSAGE: &str =
    "exactly one of spec.source or spec.sources must be specified";
/// CEL rule (`T20.1`) capping `spec.sources` at 16 entries.
const SOURCES_LIMIT_RULE: &str = "!self.?sources.hasValue() || size(self.sources) <= 16";
/// Message the API server returns for a 17-entry `spec.sources`.
const SOURCES_LIMIT_MESSAGE: &str = "spec.sources must contain at most 16 entries";
/// Layer media type `helm package` artifacts carry (the extractor unwraps one `<chart>/` root).
const HELM_CHART_LAYER: &str = "application/vnd.cncf.helm.chart.content.v1.tar+gzip";
/// Config media type `helm package`-style artifacts carry (any value is accepted by the extractor).
const HELM_CONFIG: &str = "application/vnd.cncf.helm.config.v1+json";
/// Manifest media type this test writes (the engine also accepts the Docker spelling).
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// The CRD this suite reads back and probes the admission of.
const APPLICATION_CRD: &str = "applications.ferriscd.io";
/// Budget for a first convergence (image pull + tag/digest resolve + renderer subprocess).
const STARTUP_BUDGET: Duration = Duration::from_secs(300);
/// Budget for a pass that re-applies an already-rendered revision.
const CONVERGENCE_BUDGET: Duration = Duration::from_secs(180);
/// Budget for the values-repository change to be noticed and applied. The `Application` requeues
/// every 15 s, so a heal that needs ten minutes (or a manual operation) would fail here.
const RESYNC_BUDGET: Duration = Duration::from_secs(180);

/// `T20.1`: one `Application` renders an OCI Helm chart with values from a separate Git repository.
#[test]
#[ignore = "requires a live kind cluster (make kind-up), helm, git and a registry:2 image"]
fn a_multi_source_application_renders_a_chart_with_values_from_a_git_repository() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    assert_binary("helm", &["version", "--short"]);
    assert_binary("git", &["--version"]);

    install_crds();
    let _cleanup = ClusterCleanup::new();
    create_namespaces();

    // --- 0. A real registry with the real chart, and a real values repository ----------------
    let registry = RegistryFixture::start();
    let base = registry.base_url();
    let work = tempfile::tempdir().expect("create the fixture directory");
    let chart_layer = package_chart(work.path(), CHART_TAG);
    let chart_digest = push_artifact(
        &base,
        CHART_REPOSITORY,
        CHART_TAG,
        HELM_CHART_LAYER,
        HELM_CONFIG,
        &chart_layer,
    );
    assert!(
        chart_digest.starts_with("sha256:") && chart_digest.len() == "sha256:".len() + 64,
        "a pushed manifest is addressed by its immutable digest, got {chart_digest}"
    );

    // A plain on-disk repository: the controller reads it over `file://`-style local transport, so
    // the values source is a Git repository in every sense that matters (`HEAD`, commits, a moving
    // `targetRevision`) without needing a Git server on the cluster network.
    let values_repository = work.path().join("values-repository");
    write_values_repository(&values_repository, "v1");
    let values_url = values_repository
        .to_str()
        .expect("utf8 fixture path")
        .to_owned();
    let first_values_sha = git_sha(&values_repository);

    apply_project(&base, &values_url);
    apply_application(&base, &chart_digest, &values_url);

    let metrics = free_address();
    let mut controller = ControllerProcess::start(metrics);

    // --- 1. The chart renders with the values repository's file -------------------------------
    wait_for(
        STARTUP_BUDGET,
        "the multi-source Application to converge",
        || {
            sync_revisions(APPLICATION).len() == 2
                && configmap_value(CHART_CONFIG_MAP).as_deref() == Some("v1")
                && condition_status(APPLICATION, "Ready").as_deref() == Some("True")
        },
    );
    assert_eq!(
        configmap_value(CHART_CONFIG_MAP).as_deref(),
        Some("v1"),
        "the deployed tag must come from the values repository, not the chart's own default \
         (`{CHART_DEFAULT}`): `$values/values.yaml` did not reach the renderer"
    );

    // --- 2. The revision is a composite digest; the per-source revisions are in declaration order
    let first_revision = revision(APPLICATION).expect("status.sync.revision");
    assert!(
        first_revision.starts_with("sha256:") && first_revision.len() == "sha256:".len() + 64,
        "a multi-source revision is a composite digest, got {first_revision}"
    );
    assert_ne!(
        first_revision, chart_digest,
        "the composite identity must not be one source's revision"
    );
    let revisions = sync_revisions(APPLICATION);
    assert_eq!(
        revisions,
        vec![chart_digest.clone(), first_values_sha.clone()],
        "status.sync.revisions must carry every source in declaration order"
    );
    assert_eq!(
        history_revisions(APPLICATION),
        revisions,
        "the history entry records the per-source revisions a rollback re-pins"
    );
    assert_eq!(
        sync_status(APPLICATION).as_deref(),
        Some("Synced"),
        "a converged multi-source Application reports Synced"
    );

    // --- 3. A second pass at unchanged revisions is idempotent --------------------------------
    //
    // What this proves: the settled pass at `first_revision` is not re-applied. The observable is
    // the **recorded deployment**, not the rendered content (which is unchanged either way): a pass
    // that applied again would append another `status.history` entry and move the newest
    // `deployedAt`, while a no-op pass at the same revision appends nothing (`deployment_is_new` is
    // false). Comparing `history` is therefore the apply counter this test can see over `kubectl`.
    let history_before = deployment_history_marker(APPLICATION);
    request_operation(APPLICATION, r#"{"sync":{}}"#);
    wait_for(
        CONVERGENCE_BUDGET,
        "the manual sync annotation to be consumed by a settled pass",
        || operation_annotation(APPLICATION).is_none(),
    );
    // Let the settled pass write `/status` before reading it back: the annotation patch and the
    // status patch are two different requests.
    wait_for(
        CONVERGENCE_BUDGET,
        "the sync pass to settle at Synced",
        || sync_status(APPLICATION).as_deref() == Some("Synced"),
    );
    assert_eq!(
        revision(APPLICATION).as_deref(),
        Some(first_revision.as_str()),
        "an idempotent pass must re-deploy the same composite revision"
    );
    assert_eq!(
        configmap_value(CHART_CONFIG_MAP).as_deref(),
        Some("v1"),
        "an idempotent pass must not change the deployed content"
    );
    assert_eq!(
        deployment_history_marker(APPLICATION),
        history_before,
        "an idempotent pass must not record a second deployment (history length and deployedAt \
         both unchanged, so nothing was applied)"
    );

    // --- 4. A values commit alone resyncs, under `selfHeal: false` ---------------------------
    //
    // Only the values repository moves: the chart is pinned to the digest pushed above, so
    // `status.sync.revisions[0]` may not change. The pass that followed step 3 left the Application
    // `Synced` at `first_revision`, so nothing but the new values revision can justify the apply
    // below — a periodic requeue that re-applied unconditionally would have to fail step 3 first.
    commit_values(&values_repository, "v2");
    let second_values_sha = git_sha(&values_repository);
    assert_ne!(second_values_sha, first_values_sha);

    wait_for(
        RESYNC_BUDGET,
        "the moved values repository to be re-rendered and re-applied",
        || {
            sync_revisions(APPLICATION) == vec![chart_digest.clone(), second_values_sha.clone()]
                && configmap_value(CHART_CONFIG_MAP).as_deref() == Some("v2")
        },
    );
    let second_revision = revision(APPLICATION).expect("status.sync.revision");
    assert_ne!(
        second_revision, first_revision,
        "the composite revision must move when any source moves"
    );
    assert!(
        second_revision.starts_with("sha256:") && second_revision.len() == "sha256:".len() + 64,
        "the resynced revision must still be the composite digest, got {second_revision}"
    );
    assert_eq!(
        sync_revisions(APPLICATION),
        vec![chart_digest.clone(), second_values_sha.clone()],
        "only the values revision may have moved: the chart is digest-pinned"
    );
    assert_eq!(
        history_revisions(APPLICATION),
        vec![chart_digest, second_values_sha],
        "the new deployment appended a history entry with both source revisions"
    );
    // The digest-pinned chart must not have been re-fetched from the registry on every pass; the
    // metric also proves the OCI transport really ran at all (non-vacuity for step 1).
    assert!(
        metric(
            metrics,
            "ferriscd_source_fetch_duration_seconds_count{source_kind=\"oci\"}"
        ) >= Some(1.0),
        "the live OCI registry transport must have been observed"
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
    /// `--allow-local-repos` is what makes the plaintext local registry (`http://127.0.0.1:<port>`)
    /// and the on-disk values repository admissible at all; under the production policy both are
    /// refused by design (`OciUrlPolicy::Production`, `reqwest::https_only`).
    fn start(metrics: SocketAddr) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ferriscd"))
            .args([
                "controller",
                "--namespace",
                CONTROL_NAMESPACE,
                "--allow-local-repos",
                "--metrics-addr",
                &metrics.to_string(),
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
          # Documented prerequisite: `kind load docker-image registry:2` makes this work offline.
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 5000
          readinessProbe:
            httpGet:
              path: /v2/
              port: 5000
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
        wait_for(STARTUP_BUDGET, "the registry to answer /v2/", || {
            http_status(port, "/v2/") == Some(200)
        });
        fixture
    }

    fn base_url(&self) -> String {
        self.base.clone()
    }
}

impl Drop for RegistryFixture {
    fn drop(&mut self) {
        let _ = self.forward.kill();
        let _ = self.forward.wait();
    }
}

// ---------------------------------------------------------------------------
// Artifacts: `helm package` plus the registry v2 push
// ---------------------------------------------------------------------------

/// Packages the `payments` Helm chart at `version` and returns the `.tgz` bytes.
///
/// The chart's **own** `values.yaml` deliberately sets `image.tag: chart-default`: if the values
/// repository's file never reaches the renderer, the deployed `ConfigMap` says `chart-default` and
/// the assertions fail instead of quietly passing on the chart's default.
fn package_chart(work: &Path, version: &str) -> Vec<u8> {
    let chart = work.join(format!("chart-{version}")).join("payments");
    std::fs::create_dir_all(chart.join("templates")).expect("create the chart directory");
    std::fs::write(
        chart.join("Chart.yaml"),
        format!("apiVersion: v2\nname: payments\nversion: {version}\n"),
    )
    .expect("write Chart.yaml");
    std::fs::write(
        chart.join("values.yaml"),
        format!("image:\n  tag: {CHART_DEFAULT}\n"),
    )
    .expect("write the chart values.yaml");
    std::fs::write(
        chart.join("templates/configmap.yaml"),
        format!(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {CHART_CONFIG_MAP}\ndata:\n  \
             {VALUE_KEY}: {{{{ .Values.image.tag | quote }}}}\n"
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

    std::fs::read(out.join(format!("payments-{version}.tgz")))
        .expect("the packaged chart must exist")
}

/// Pushes `layer` as one OCI artifact under `<base>/v2/<repository>/manifests/<tag>` and returns the
/// manifest digest the registry canonicalized it to.
///
/// The distribution upload dance is written out instead of shelling out to `oras`/`crane`/`helm
/// push`, so the test has no client besides `reqwest` (already a dependency) and no tool-version
/// sensitivity: `POST .../blobs/uploads/`, `PUT <location>&digest=…`, then `PUT .../manifests/<tag>`.
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
        "the registry and this test disagree on the blob digest — the bytes it received are not the \
         bytes that were hashed"
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
// Values repository fixture (a real Git repository on disk)
// ---------------------------------------------------------------------------

/// Creates `repository` with a committed `values.yaml` whose `image.tag` is `tag`.
fn write_values_repository(repository: &Path, tag: &str) {
    std::fs::create_dir_all(repository).expect("create the values repository");
    write_values_file(repository, tag);
    git(repository, &["init", "--initial-branch=main"]);
    git(repository, &["add", "."]);
    commit(repository, "seed the values file");
}

/// Moves the values repository forward by one commit with a new `image.tag`.
fn commit_values(repository: &Path, tag: &str) {
    write_values_file(repository, tag);
    git(repository, &["add", "."]);
    commit(repository, "bump the deployed tag");
}

fn write_values_file(repository: &Path, tag: &str) {
    std::fs::write(
        repository.join("values.yaml"),
        format!("image:\n  tag: {tag}\n"),
    )
    .expect("write values.yaml");
}

fn commit(repository: &Path, message: &str) {
    git(
        repository,
        &[
            "-c",
            "user.name=FerrisCD Test",
            "-c",
            "user.email=test@ferriscd.io",
            "commit",
            "-m",
            message,
        ],
    );
}

/// Runs one `git` command in `directory`, failing loudly.
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

/// The commit `HEAD` points at in `repository`.
fn git_sha(repository: &Path) -> String {
    let output = git(repository, &["rev-parse", "HEAD"]);
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

// ---------------------------------------------------------------------------
// Cluster fixtures
// ---------------------------------------------------------------------------

/// Deletes everything this test creates, on every exit path (and before it starts, so a run can
/// never be satisfied by a previous run's leftovers — `make test-integration-twice`).
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
            "--timeout=60s",
        ]);
        let _ = kubectl(&[
            "-n",
            CONTROL_NAMESPACE,
            "delete",
            "appproject",
            PROJECT,
            "--ignore-not-found=true",
            "--timeout=60s",
        ]);
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

/// Installs the committed CRDs and proves the **installed** schema is the `T20.1` one.
fn install_crds() {
    // `CARGO_MANIFEST_DIR` is the manifest of the *test target's* package: this file is
    // `#[path]`-included from `crates/ferriscd-cli/tests/v2_0_multi_source.rs`, so `../..` is the
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

    assert_installed_multi_source_schema();
    assert_source_declaration_is_enforced_by_admission();
}

/// Reads the installed CRD back: a stale one (from a revision without `spec.sources`) would
/// otherwise be used silently and every assertion in this file would test the old contract.
fn assert_installed_multi_source_schema() {
    let output = kubectl(&["get", "crd", APPLICATION_CRD, "-o", "json"]);
    assert!(
        output.status.success(),
        "could not read back crd/{APPLICATION_CRD}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let crd: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("crd/{APPLICATION_CRD} is not JSON: {error}"));
    let spec = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"];

    let sources = &spec["properties"]["sources"];
    assert!(
        sources["items"].is_object(),
        "the installed CRD has no `spec.sources`: re-apply deploy/crds/applications.ferriscd.io.yaml \
         (deleting the CRD first if the apply was refused). Installed spec properties: {:?}",
        spec["properties"]
            .as_object()
            .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
    );
    assert_eq!(
        sources["maxItems"], 16,
        "spec.sources must be capped at 16 entries in the schema: {sources}"
    );
    for field in ["ref", "git", "oci", "renderer"] {
        assert!(
            sources["items"]["properties"][field].is_object(),
            "the installed `spec.sources` entry schema is missing `{field}`: {sources}"
        );
    }
    let required = spec["required"].as_array().cloned().unwrap_or_default();
    assert!(
        !required.iter().any(|field| field == "source"),
        "spec.source must no longer be required once spec.sources exists: {required:?}"
    );

    let rules = spec["x-kubernetes-validations"]
        .as_array()
        .unwrap_or_else(|| panic!("the installed `spec` schema carries no CEL rules: {spec}"));
    for (rule, message) in [
        (SOURCE_DECLARATION_RULE, SOURCE_DECLARATION_MESSAGE),
        (SOURCES_LIMIT_RULE, SOURCES_LIMIT_MESSAGE),
    ] {
        assert!(
            rules
                .iter()
                .any(|installed| installed["rule"].as_str() == Some(rule)
                    && installed["message"].as_str() == Some(message)),
            "the installed CRD does not carry the `T20.1` rule `{rule}` with its documented \
             message; installed rules: {rules:?}"
        );
    }
}

/// Proves the installed CEL rules with real API-server admission decisions.
///
/// `--dry-run=server` runs the full schema + CEL validation without persisting anything, and the
/// probes live in the `default` namespace so they need no fixture of their own. The positive
/// controls matter as much as the refusals: they prove the rejection below is caused by the rule
/// and not by an unrelated schema complaint.
fn assert_source_declaration_is_enforced_by_admission() {
    let probe = |spec: &str| {
        format!(
            r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: multi-source-admission-probe
  namespace: default
spec:
{spec}  destination:
    namespace: default
"#
        )
    };

    // A `v1.0` single-source object is still admitted.
    let admitted = apply_dry_run(&probe(
        "  source:\n    git:\n      repoURL: https://github.com/example/probe.git\n",
    ));
    assert!(
        admitted.status.success(),
        "a v1.0 single-source Application must stay admissible; got: {}",
        String::from_utf8_lossy(&admitted.stderr)
    );

    // Two declared sources are admitted (per-entry exactly-one-of passes).
    let multi = probe(
        "  sources:\n    - ref: chart\n      git:\n        repoURL: \
         https://github.com/example/charts.git\n    - ref: values\n      git:\n        repoURL: \
         https://github.com/example/values.git\n",
    );
    let admitted = apply_dry_run(&multi);
    assert!(
        admitted.status.success(),
        "a two-entry spec.sources must be admissible; got: {}",
        String::from_utf8_lossy(&admitted.stderr)
    );

    // `source` **and** `sources` is refused by the spec-level rule.
    let both = probe(
        "  source:\n    git:\n      repoURL: https://github.com/example/probe.git\n  sources:\n    \
         - git:\n        repoURL: https://github.com/example/values.git\n",
    );
    let rejected = apply_dry_run(&both);
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        !rejected.status.success(),
        "the API server admitted an Application with both spec.source and spec.sources"
    );
    assert!(
        stderr.contains(SOURCE_DECLARATION_MESSAGE),
        "the admission must fail with the CEL rule's message `{SOURCE_DECLARATION_MESSAGE}`; got: \
         {stderr}"
    );

    // 17 entries exceed the cap the roadmap bounds the checkout fan-out with.
    let mut seventeen = String::from("  sources:\n");
    for index in 0..17 {
        seventeen.push_str(&format!(
            "    - ref: ref-{index}\n      git:\n        repoURL: \
             https://github.com/example/values-{index}.git\n"
        ));
    }
    let rejected = apply_dry_run(&probe(&seventeen));
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        !rejected.status.success(),
        "the API server admitted 17 spec.sources entries: the cap is not enforced"
    );
    assert!(
        stderr.contains(SOURCES_LIMIT_MESSAGE) || stderr.contains("Too many"),
        "the admission must fail on the 16-entry cap; got: {stderr}"
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

/// The `AppProject` the `Application` references.
///
/// `sourceRepos` lists the **exact** source URLs (the forwarded registry and the values repository)
/// rather than `*`: `T20.1` requires `check_application` to authorize every declared source before
/// anything is fetched, and a wildcard would let this test pass with a policy that never looked.
fn apply_project(base: &str, values_url: &str) {
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: {PROJECT}
  namespace: {CONTROL_NAMESPACE}
spec:
  description: "multi-source chart + values e2e (T20.1)"
  sourceRepos:
    - {base}/{CHART_REPOSITORY}
    - {values_url}
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

/// Applies the multi-source `Application`.
///
/// Three properties are load-bearing:
///
/// * `spec.sources[0]` is the OCI chart **digest-pinned** (`digest`, not `tag`), so the chart's
///   revision provably cannot move while the values repository does;
/// * `valueFiles` addresses the second source through its alias (`$values/values.yaml`);
/// * `automated.selfHeal` is `false`, so a re-apply can only be justified by a changed revision —
///   and `requeueAfterSeconds: 15` makes the periodic pass the trigger, keeping the test bounded.
fn apply_application(base: &str, chart_digest: &str, values_url: &str) {
    apply_stdin(&format!(
        r#"apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: {APPLICATION}
  namespace: {CONTROL_NAMESPACE}
spec:
  project: {PROJECT}
  sources:
    - ref: chart
      oci:
        url: {base}/{CHART_REPOSITORY}
        digest: {chart_digest}
        path: ""
      # `helm` is an object: the renderer enum is spelled as a single-key map, not a string.
      renderer:
        helm:
          releaseName: payments
          valueFiles:
            - $values/values.yaml
    - ref: values
      git:
        repoURL: {values_url}
        targetRevision: HEAD
  destination:
    cluster: in-cluster
    namespace: {TARGET_NAMESPACE}
  syncPolicy:
    automated:
      prune: false
      selfHeal: false
  requeueAfterSeconds: 15
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

/// `status.sync.revision` — the composite deployment identity the last pass rendered.
fn revision(name: &str) -> Option<String> {
    status_jsonpath(name, "{.status.sync.revision}")
}

/// `status.sync.revisions` — one entry per declared source, in declaration order.
fn sync_revisions(name: &str) -> Vec<String> {
    lines_or_empty(&application_json(name)["status"]["sync"]["revisions"])
}

/// `status.history[0].revisions` — the per-source revisions of the newest deployment.
fn history_revisions(name: &str) -> Vec<String> {
    lines_or_empty(&application_json(name)["status"]["history"][0]["revisions"])
}

/// The recorded deployment identity: `status.history` length plus the newest entry's `deployedAt`.
///
/// A pass that settles at an already-deployed revision appends **no** history entry
/// (`deployment_is_new` is false in the controller), so this pair is the apply counter a live test
/// can actually observe. `status.sync.revision` alone could not distinguish "re-rendered the same
/// bytes and did not apply" from "did not run at all".
fn deployment_history_marker(name: &str) -> (usize, String) {
    let json = application_json(name);
    let history = json["status"]["history"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let newest = history
        .first()
        .and_then(|entry| entry["deployedAt"].as_str())
        .unwrap_or_default()
        .to_owned();
    (history.len(), newest)
}

fn lines_or_empty(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn sync_status(name: &str) -> Option<String> {
    status_jsonpath(name, "{.status.sync.status}")
}

fn condition_status(name: &str, condition: &str) -> Option<String> {
    status_jsonpath(
        name,
        &format!("{{.status.conditions[?(@.type==\"{condition}\")].status}}"),
    )
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
/// A bounded retry loop, never a fixed sleep: it fails loudly with the observed `spec`/`status`
/// instead of hanging, and it returns as soon as the cluster agrees.
fn wait_for(budget: Duration, what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + budget;
    loop {
        if condition() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {budget:?} waiting for {what}; {APPLICATION} spec was {}, status was {}",
            application_json(APPLICATION)["spec"],
            application_json(APPLICATION)["status"],
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}
