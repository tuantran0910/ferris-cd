//! Live `v0.4` renderer test: render the Phase 11 examples with the **real** `kustomize v5` /
//! `helm v4` binaries through FerrisCD's render pipeline, then apply the result to a live `kind`
//! cluster.
//!
//! # Safety gate
//!
//! Every test first asserts that `kubectl config current-context` starts with `kind-`, mirroring
//! the `test-integration` Makefile guard. Both tests are `#[ignore]`d so `make gate` (hermetic,
//! no external binaries) never runs them; invoke them explicitly:
//!
//! ```text
//! make kind-up
//! cargo test -p ferriscd-engine --test v0_4_renderers -- --ignored
//! ```
//!
//! # What these tests prove beyond the unit tests
//!
//! * the renderer's argv is accepted by the real binaries (no invented flags),
//! * `--load-restrictor=LoadRestrictionsRootOnly` plus the scratch post-build overlay really works
//!   for `namePrefix`/`images` without touching the checkout,
//! * `helm template ... --kube-version` renders `.Capabilities.KubeVersion` offline, and
//!   `crds/` stays out of the bundle unless `includeCRDs` is set,
//! * all rendered output survives the Phase 03/04 pipeline (parse + normalize) and applies cleanly.

// Test-only shell-out helpers are allowed to panic: this file is compiled as a test target only.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ferriscd_engine::manifest::{
    HelmOptions, KustomizeOptions, RenderContext, RenderPipeline, RendererConfig,
};

const KUSTOMIZE_NAMESPACE: &str = "ferriscd-render";
const HELM_NAMESPACE: &str = "ferriscd-render-helm";
const HELM_RELEASE: &str = "render-demo";
const COMMIT_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

/// Renders `examples/kustomize/overlays/prod`, applies it, and verifies the objects and the
/// `namePrefix`/`images` transforms against a live cluster.
#[test]
#[ignore = "requires a live kind cluster (make kind-up) and kustomize v5 installed"]
fn kustomize_example_overlay_renders_and_applies_on_kind() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    assert_binary("kustomize");
    let _cleanup = NamespaceCleanup::new(KUSTOMIZE_NAMESPACE);

    let examples = examples_root();
    let checkout = examples.join("kustomize");
    let pipeline = RenderPipeline::new(8);

    let plain = RenderContext::new(&checkout)
        .with_repo_url("https://example.com/ferris-cd/examples.git")
        .with_commit_sha(COMMIT_SHA)
        .with_source_path("overlays/prod")
        .with_app("ferriscd-system", "kustomize-example")
        .with_destination_namespace(KUSTOMIZE_NAMESPACE)
        .with_kube_version(kube_version())
        .with_renderer(RendererConfig::Kustomize(KustomizeOptions::default()));

    let rendered = block_on(pipeline.render(&plain)).expect("kustomize render");
    let kinds: Vec<String> = rendered
        .iter()
        .map(|resource| resource.gvk.kind.clone())
        .collect();
    for expected in ["Namespace", "ConfigMap", "Deployment", "Service"] {
        assert!(
            kinds.iter().any(|kind| kind == expected),
            "rendered bundle is missing {expected}: {kinds:?}"
        );
    }
    let deployment = rendered
        .iter()
        .find(|resource| resource.key.kind == "Deployment")
        .expect("deployment resource");
    assert_eq!(
        deployment
            .object
            .data
            .pointer("/spec/replicas")
            .and_then(serde_json::Value::as_u64),
        Some(3),
        "the overlay patch must set replicas: 3"
    );

    // The `namePrefix` + `images` transforms run through the scratch overlay; assert them on the
    // rendered text without renaming the objects that get applied below.
    let prefixed = block_on(pipeline.render(&RenderContext {
        app_name: "kustomize-prefixed".to_owned(),
        renderer: RendererConfig::Kustomize(KustomizeOptions {
            name_prefix: Some("prod-".to_owned()),
            images: vec!["nginx=nginx:1.27-alpine".to_owned()],
            ..KustomizeOptions::default()
        }),
        ..plain.clone()
    }))
    .expect("prefixed render");
    let prefixed_deployment = prefixed
        .iter()
        .find(|resource| resource.key.kind == "Deployment")
        .expect("prefixed deployment");
    assert_eq!(prefixed_deployment.key.name, "prod-render-app");
    assert_eq!(
        prefixed_deployment
            .object
            .data
            .pointer("/spec/template/spec/containers/0/image")
            .and_then(serde_json::Value::as_str),
        Some("nginx:1.27-alpine"),
        "the images transform must be applied by the scratch overlay"
    );

    let bundle = manifest_text(&rendered);
    kubectl_apply(&bundle);

    wait_for(Duration::from_secs(180), "the Deployment to exist", || {
        object_exists("deployment", "render-app", KUSTOMIZE_NAMESPACE)
    });
    wait_for(Duration::from_secs(120), "the Service to exist", || {
        object_exists("service", "render-app", KUSTOMIZE_NAMESPACE)
    });
    assert!(
        object_exists("configmap", "render-config", KUSTOMIZE_NAMESPACE),
        "the ConfigMap from the base must exist"
    );
    assert!(
        object_exists("namespace", KUSTOMIZE_NAMESPACE, ""),
        "the kustomize-rendered Namespace must exist"
    );
    assert!(
        object_absent("customresourcedefinition", "widgets.example.com", ""),
        "the kustomize example ships no CRDs"
    );
}

/// Renders `examples/helm` with a custom `valueFiles` entry plus inline values, applies it, and
/// verifies CRDs are omitted by default.
#[test]
#[ignore = "requires a live kind cluster (make kind-up) and helm v4 installed"]
fn helm_example_renders_with_values_and_omits_crds_on_kind() {
    let context = current_kube_context();
    assert!(
        context.starts_with("kind-"),
        "refusing to touch non-kind cluster context '{context}'"
    );
    assert_binary("helm");
    let _cleanup = NamespaceCleanup::new(HELM_NAMESPACE);

    let examples = examples_root();
    let checkout = examples.join("helm");
    let pipeline = RenderPipeline::new(8);

    let ctx = RenderContext::new(&checkout)
        .with_repo_url("https://example.com/ferris-cd/examples.git")
        .with_commit_sha(COMMIT_SHA)
        .with_source_path(".")
        .with_app("ferriscd-system", HELM_RELEASE)
        .with_destination_namespace(HELM_NAMESPACE)
        .with_kube_version(kube_version())
        .with_renderer(RendererConfig::Helm(HelmOptions {
            value_files: vec!["values-prod.yaml".to_owned()],
            inline_values: Some("replicaCount: 2\n".to_owned()),
            ..HelmOptions::default()
        }));

    let rendered = block_on(pipeline.render(&ctx)).expect("helm render");

    // Finding H3: `crds/` must stay out of the bundle unless includeCRDs is requested.
    assert!(
        rendered
            .iter()
            .all(|resource| resource.gvk.kind != "CustomResourceDefinition"),
        "helm must not manage CRDs unless includeCRDs is set"
    );

    let deployment = rendered
        .iter()
        .find(|resource| resource.key.kind == "Deployment")
        .expect("deployment resource");
    assert_eq!(
        deployment
            .object
            .data
            .pointer("/spec/replicas")
            .and_then(serde_json::Value::as_u64),
        Some(2),
        "inline values must win over the values file"
    );
    let configmap = rendered
        .iter()
        .find(|resource| resource.key.kind == "ConfigMap")
        .expect("configmap resource");
    assert_eq!(
        configmap
            .object
            .data
            .pointer("/data/APP_ENV")
            .and_then(serde_json::Value::as_str),
        Some("prod"),
        "values-prod.yaml must be applied"
    );
    assert_eq!(
        deployment.key.namespace.as_deref(),
        Some(HELM_NAMESPACE),
        "`--namespace` must reach `.Release.Namespace`"
    );

    let bundle = manifest_text(&rendered);
    create_namespace(HELM_NAMESPACE);
    kubectl_apply(&bundle);

    wait_for(Duration::from_secs(180), "the Deployment to exist", || {
        object_exists("deployment", HELM_RELEASE, HELM_NAMESPACE)
    });
    wait_for(Duration::from_secs(120), "the ConfigMap to exist", || {
        object_exists(
            "configmap",
            &format!("{HELM_RELEASE}-config"),
            HELM_NAMESPACE,
        )
    });

    // Opting in is the only way a chart CRD enters the bundle.
    let with_crds = RenderContext {
        renderer: RendererConfig::Helm(HelmOptions {
            value_files: vec!["values-prod.yaml".to_owned()],
            include_crds: true,
            ..HelmOptions::default()
        }),
        ..ctx.clone()
    };
    let rendered = block_on(pipeline.render(&with_crds)).expect("helm render with CRDs");
    assert!(
        rendered
            .iter()
            .any(|resource| resource.gvk.kind == "CustomResourceDefinition"),
        "includeCRDs: true must render the chart CRDs"
    );
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

fn examples_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .canonicalize()
        .expect("resolve the workspace examples directory")
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build a Tokio runtime")
        .block_on(future)
}

fn current_kube_context() -> String {
    let output = Command::new("kubectl")
        .args(["config", "current-context"])
        .output()
        .expect("run kubectl config current-context");
    assert!(
        output.status.success(),
        "kubectl config current-context failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn assert_binary(name: &str) {
    let output = Command::new(name)
        .arg("version")
        .output()
        .unwrap_or_else(|err| panic!("{name} must be installed for this live test: {err}"));
    assert!(
        output.status.success(),
        "{name} version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn kube_version() -> String {
    let output = Command::new("kubectl")
        .args(["version", "-o", "json"])
        .output()
        .expect("run kubectl version");
    let text = String::from_utf8_lossy(&output.stdout);
    // `gitVersion` is `v1.35.0`; the engines only need `major.minor`.
    for token in ["\"major\": \"", "\"minor\": \""] {
        assert!(
            text.contains(token),
            "unexpected kubectl version output: {text}"
        );
    }
    let major = json_string_after(&text, "\"major\": \"").unwrap_or_else(|| "1".to_owned());
    let minor = json_string_after(&text, "\"minor\": \"").unwrap_or_else(|| "35".to_owned());
    let minor = minor.trim_end_matches('+').to_owned();
    format!("{major}.{minor}")
}

fn json_string_after(text: &str, needle: &str) -> Option<String> {
    let start = text.find(needle)? + needle.len();
    let rest = &text[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// Serializes normalized resources back into a multi-document YAML/JSON bundle for `kubectl`.
fn manifest_text(resources: &[ferriscd_engine::manifest::DesiredResource]) -> String {
    let mut bundle = String::new();
    for resource in resources {
        bundle.push_str(
            &serde_json::to_string(&resource.object).expect("serialize a rendered resource"),
        );
        bundle.push('\n');
        bundle.push_str("---\n");
    }
    bundle
}

fn kubectl_apply(bundle: &str) {
    use std::io::Write as _;

    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kubectl apply");
    child
        .stdin
        .as_mut()
        .expect("kubectl stdin")
        .write_all(bundle.as_bytes())
        .expect("write the rendered bundle to kubectl");
    let output = child.wait_with_output().expect("kubectl apply output");
    assert!(
        output.status.success(),
        "kubectl apply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_namespace(namespace: &str) {
    let output = Command::new("kubectl")
        .args(["create", "namespace", namespace])
        .output()
        .expect("run kubectl create namespace");
    assert!(
        output.status.success()
            || String::from_utf8_lossy(&output.stderr).contains("AlreadyExists"),
        "kubectl create namespace {namespace} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn object_exists(kind: &str, name: &str, namespace: &str) -> bool {
    let mut command = Command::new("kubectl");
    command.args(["get", kind, name]);
    if !namespace.is_empty() {
        command.args(["-n", namespace]);
    }
    command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn object_absent(kind: &str, name: &str, namespace: &str) -> bool {
    !object_exists(kind, name, namespace)
}

fn wait_for(timeout: Duration, what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("timed out after {timeout:?} waiting for {what}");
}

/// Deletes the target namespace (and everything in it) when the test ends.
struct NamespaceCleanup {
    namespace: &'static str,
}

impl NamespaceCleanup {
    fn new(namespace: &'static str) -> Self {
        Self { namespace }
    }
}

impl Drop for NamespaceCleanup {
    fn drop(&mut self) {
        let _ = Command::new("kubectl")
            .args([
                "delete",
                "namespace",
                self.namespace,
                "--ignore-not-found",
                "--wait=false",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
