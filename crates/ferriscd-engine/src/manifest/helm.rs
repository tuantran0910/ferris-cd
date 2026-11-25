//! `helm template` renderer (Helm v4) with opt-in CRDs, `--kube-version`, and a path jail.
//!
//! # Offline by construction
//!
//! Only `helm template` is ever invoked: it renders charts locally and never talks to a cluster,
//! so `.Capabilities` comes from `--kube-version` (fed from the destination cluster's discovered
//! server version) instead of a live API call. Combined with the sandbox's cleared environment and
//! dead proxy endpoints, a chart cannot phone home during a render.
//!
//! # CRDs are opt-in
//!
//! `crds/` content is installed by `helm install` by default, but *pruning* a CRD deletes every
//! custom resource of that type. FerrisCD therefore never passes `--include-crds` unless
//! `spec.source.renderer.helm.includeCRDs` is explicitly `true` (Finding H3). When it is enabled
//! the CRDs enter the normal pipeline and are owned/tracked like any other rendered resource.
//!
//! # Values handling
//!
//! * `valueFiles` are resolved relative to `spec.source.git.path` and must canonicalize **inside**
//!   the checkout root (Trap T11). `--values` also accepts URLs in Helm, so remote values paths are
//!   rejected before the subprocess runs.
//! * inline `values` are written to a per-invocation scratch file, never to argv or the worktree.
//! * `--set` / `--set-string` entries are passed as separate `OsStr` arguments — there is no shell,
//!   so `;`, `$(...)`, quotes, and spaces are literal values, never commands.
//! * the release name and namespace are validated against Kubernetes naming rules first, because a
//!   value like `--post-renderer=/tmp/evil.sh` passed as a positional argument would otherwise be
//!   parsed by Helm's flag parser as a flag.
//!
//! # Capabilities are mandatory, hooks are excluded
//!
//! `--kube-version` is **always** passed: an empty discovered version is a render error
//! (`RendererRejected`), never a silent fallback to helm's compiled-in version, because
//! `.Capabilities.KubeVersion` legitimately changes what a chart renders (finding M3).
//!
//! `--no-hooks` is always passed too (finding M4). `helm template` would otherwise inline
//! `helm.sh/hook*` resources into the rendered stream, where this pipeline would treat them as
//! ordinary managed objects: a hook `Job` would be applied, diffed `OutOfSync` forever, and — with
//! `automated.prune` — deleted like a workload, while `PreSync`/`PostSync` ordering was never
//! honoured. Lifecycle hooks are Phase 10/12 work, so they stay out of the bundle entirely.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ferriscd_crd::HelmRenderer as CrdHelmRenderer;

use super::error::ManifestError;
use super::exec::{ExecError, SandboxedCommand};
use super::loader::ManifestFile;
use super::renderer::{
    CHART_FILE, ManifestRenderer, RenderContext, RenderFuture, RendererKind, canonical_root,
    contained_file, is_remote_reference, relative_display, resolve_relative_inside,
    resolve_source_path, task_failed,
};

/// Renderer name used in errors and logs.
const RENDERER: &str = "helm";

/// Chart file that must exist for `helm template` to succeed.
const VALUES_FILE: &str = "values.yaml";

/// Fallback release name when neither the renderer nor the `Application` supplies one.
const DEFAULT_RELEASE_NAME: &str = "ferriscd";

/// Maximum Helm release name length (Helm enforces 53).
const MAX_RELEASE_NAME: usize = 53;

/// Helm renderer configuration.
///
/// `binary`, `timeout`, and `max_output_bytes` are engine/operator knobs and are excluded from the
/// render cache key: they change *whether* a render can run, not what it renders.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct HelmOptions {
    /// Release name; defaults to the `Application` name.
    pub release_name: Option<String>,
    /// Values files relative to `spec.source.git.path`.
    pub value_files: Vec<String>,
    /// Inline values YAML written to a scratch file and passed with `--values`.
    pub inline_values: Option<String>,
    /// `--set key=value` pairs, passed as separate arguments.
    pub set: Vec<String>,
    /// `--set-string key=value` pairs, passed as separate arguments.
    pub set_string: Vec<String>,
    /// Install the chart's `crds/` directory (default `false`).
    pub include_crds: bool,
    /// Overrides the `helm` binary: an absolute path or a bare `PATH` name (relative paths are
    /// rejected by the sandbox).
    pub binary: Option<PathBuf>,
    /// Overrides the hard execution deadline.
    pub timeout: Option<Duration>,
    /// Overrides the bounded output cap.
    pub max_output_bytes: Option<u64>,
}

impl std::fmt::Debug for HelmOptions {
    /// Redacts `inline_values`: a values file is exactly where repository-held secrets live, and
    /// this struct is logged by callers.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inline = self
            .inline_values
            .as_ref()
            .map(|values| format!("<redacted {} bytes>", values.len()));
        f.debug_struct("HelmOptions")
            .field("release_name", &self.release_name)
            .field("value_files", &self.value_files)
            .field("inline_values", &inline)
            .field("set", &format!("<{} entries>", self.set.len()))
            .field(
                "set_string",
                &format!("<{} entries>", self.set_string.len()),
            )
            .field("include_crds", &self.include_crds)
            .field("binary", &self.binary)
            .field("timeout", &self.timeout)
            .field("max_output_bytes", &self.max_output_bytes)
            .finish()
    }
}

impl HelmOptions {
    /// Maps the CRD's `spec.source.renderer.helm` onto engine options.
    #[must_use]
    pub fn from_crd(spec: &CrdHelmRenderer) -> Self {
        Self {
            release_name: spec.release_name.clone(),
            value_files: spec.value_files.clone(),
            include_crds: spec.include_crds,
            ..Self::default()
        }
    }
}

/// `helm template` renderer.
#[derive(Clone, Debug, Default)]
pub struct HelmRenderer {
    options: HelmOptions,
}

impl HelmRenderer {
    /// Creates a renderer with the given options.
    #[must_use]
    pub fn new(options: HelmOptions) -> Self {
        Self { options }
    }
}

impl ManifestRenderer for HelmRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Helm
    }

    fn render<'a>(&'a self, ctx: &'a RenderContext) -> RenderFuture<'a, Vec<ManifestFile>> {
        Box::pin(async move {
            let root = ctx.root_dir.clone();
            let source_path = ctx.source_path.clone();
            let options = self.options.clone();

            let prepared =
                tokio::task::spawn_blocking(move || prepare(&root, &source_path, &options))
                    .await
                    .map_err(|join_err| task_failed(RendererKind::Helm, join_err))??;

            let args = template_args(ctx, &self.options, &prepared)?;

            let program = self
                .options
                .binary
                .clone()
                .unwrap_or_else(|| PathBuf::from(RENDERER));
            let mut command = SandboxedCommand::new(program.into_os_string())
                .args(args)
                .current_dir(&prepared.chart_dir);
            if let Some(timeout) = self.options.timeout {
                command = command.timeout(timeout);
            }
            if let Some(max_bytes) = self.options.max_output_bytes {
                command = command.max_output_bytes(max_bytes);
            }

            let output = command.run().await.map_err(map_exec_error)?;
            Ok(vec![ManifestFile {
                source_file: format!("helm:{}", prepared.relative_chart),
                contents: output.stdout,
            }])
        })
    }
}

/// Blocking preparation result: the validated chart directory and the scratch values file.
#[derive(Debug)]
struct PreparedHelm {
    chart_dir: PathBuf,
    relative_chart: String,
    /// Absolute, checkout-contained value-file paths in the order the user declared them.
    value_files: Vec<PathBuf>,
    inline_values_file: Option<PathBuf>,
    _scratch: tempfile::TempDir,
}

fn prepare(
    root: &Path,
    source_path: &str,
    options: &HelmOptions,
) -> Result<PreparedHelm, ManifestError> {
    let canonical = canonical_root(root)?;
    let chart_dir = resolve_source_path(&canonical, source_path)?;
    if !chart_dir.is_dir() {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "'{}' is not a directory",
                relative_display(&canonical, &chart_dir)
            ),
        });
    }
    if contained_file(&canonical, &chart_dir.join(CHART_FILE))?.is_none() {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "'{}' has no {CHART_FILE}; Helm can only render a chart directory",
                relative_display(&canonical, &chart_dir)
            ),
        });
    }

    let scratch = tempfile::Builder::new()
        .prefix("ferriscd-helm-")
        .tempdir()
        .map_err(|source| ManifestError::Io {
            context: "creating the helm scratch directory".to_owned(),
            source,
        })?;

    // Every value file must be a real file inside the checkout (Trap T11).
    let mut value_files = Vec::with_capacity(options.value_files.len());
    for value_file in &options.value_files {
        value_files.push(validate_value_file(&canonical, &chart_dir, value_file)?);
    }

    let inline_values_file = match options.inline_values.as_deref() {
        Some(values) if !values.trim().is_empty() => {
            let path = scratch.path().join(VALUES_FILE);
            std::fs::write(&path, values).map_err(|source| ManifestError::Io {
                context: "writing inline Helm values to scratch space".to_owned(),
                source,
            })?;
            Some(path)
        }
        _ => None,
    };

    let relative_chart = relative_display(&canonical, &chart_dir);
    Ok(PreparedHelm {
        chart_dir,
        relative_chart,
        value_files,
        inline_values_file,
        _scratch: scratch,
    })
}

/// Rejects remote, escaping, or missing `valueFiles` entries.
fn validate_value_file(
    root: &Path,
    chart_dir: &Path,
    value_file: &str,
) -> Result<PathBuf, ManifestError> {
    if is_remote_reference(value_file) {
        return Err(ManifestError::UnsafeReference {
            file: relative_display(root, chart_dir),
            field: "valueFiles".to_owned(),
            reference: value_file.to_owned(),
            reason: "Helm accepts URLs for --values, so only checkout-local files are allowed"
                .to_owned(),
        });
    }

    let resolved =
        resolve_relative_inside(root, chart_dir, value_file).map_err(|err| match err {
            ManifestError::PathEscape { path, .. } => ManifestError::UnsafeReference {
                file: relative_display(root, chart_dir),
                field: "valueFiles".to_owned(),
                reference: value_file.to_owned(),
                reason: format!("resolves outside the checkout root ('{path}')"),
            },
            other => other,
        })?;

    if !resolved.is_file() {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!("values file '{value_file}' is not a regular file"),
        });
    }

    Ok(resolved)
}

/// Builds the exact `helm template` argv (pure, so tests can pin it).
fn template_args(
    ctx: &RenderContext,
    options: &HelmOptions,
    prepared: &PreparedHelm,
) -> Result<Vec<OsString>, ManifestError> {
    let release = match options.release_name.as_deref() {
        Some(name) if !name.trim().is_empty() => name.trim().to_owned(),
        _ => {
            let application_name = ctx.app_name.trim();
            if application_name.is_empty() {
                DEFAULT_RELEASE_NAME.to_owned()
            } else {
                application_name.to_owned()
            }
        }
    };
    validate_release_name(&release)?;

    let mut args: Vec<OsString> = vec![
        OsString::from("template"),
        OsString::from(&release),
        prepared.chart_dir.clone().into_os_string(),
    ];

    let namespace = ctx.destination_namespace.trim();
    if !namespace.is_empty() {
        validate_namespace(namespace)?;
        args.push(OsString::from("--namespace"));
        args.push(OsString::from(namespace));
    }

    // Finding M3: `.Capabilities.KubeVersion` is part of what a chart renders, so a missing
    // discovered version must fail loudly instead of silently rendering with helm's built-in one.
    let kube_version = ctx.cluster_kube_version.trim();
    if kube_version.is_empty() {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: "the destination cluster kube version is empty: refusing to run `helm \
                      template` without --kube-version (refresh the discovery snapshot first, so \
                      .Capabilities.KubeVersion matches the destination cluster)"
                .to_owned(),
        });
    }
    validate_kube_version(kube_version)?;
    args.push(OsString::from("--kube-version"));
    args.push(OsString::from(kube_version));

    // Finding M4: chart hooks must never enter the managed inventory (see the module docs).
    args.push(OsString::from("--no-hooks"));

    // Finding H3: CRDs are never managed unless the Application opts in.
    if options.include_crds {
        args.push(OsString::from("--include-crds"));
    }

    for value_file in &prepared.value_files {
        args.push(OsString::from("--values"));
        args.push(value_file.clone().into_os_string());
    }
    if let Some(inline) = &prepared.inline_values_file {
        args.push(OsString::from("--values"));
        args.push(inline.clone().into_os_string());
    }

    for pair in &options.set {
        args.push(OsString::from("--set"));
        args.push(OsString::from(pair));
    }
    for pair in &options.set_string {
        args.push(OsString::from("--set-string"));
        args.push(OsString::from(pair));
    }

    Ok(args)
}

/// Rejects a release name Helm would misinterpret (or refuse) — including flag-shaped names.
fn validate_release_name(name: &str) -> Result<(), ManifestError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_RELEASE_NAME
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        && !name.starts_with('-')
        && !name.starts_with('.')
        && !name.ends_with('-')
        && !name.ends_with('.');
    if valid {
        return Ok(());
    }
    Err(ManifestError::RendererRejected {
        renderer: RENDERER.to_owned(),
        message: format!(
            "release name '{name}' is not a valid Helm release name (lowercase alphanumerics, \
             '-' and '.', at most {MAX_RELEASE_NAME} characters)"
        ),
    })
}

/// Rejects a namespace that is not a DNS-1123 label (also blocks flag-shaped values).
fn validate_namespace(namespace: &str) -> Result<(), ManifestError> {
    let valid = !namespace.is_empty()
        && namespace.len() <= 63
        && namespace
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !namespace.starts_with('-')
        && !namespace.ends_with('-');
    if valid {
        return Ok(());
    }
    Err(ManifestError::RendererRejected {
        renderer: RENDERER.to_owned(),
        message: format!("destination namespace '{namespace}' is not a valid DNS-1123 label"),
    })
}

/// Rejects a kube version that is not a plain `major.minor[.patch]` string.
fn validate_kube_version(version: &str) -> Result<(), ManifestError> {
    let trimmed = version.trim().trim_start_matches('v');
    let valid = !trimmed.is_empty()
        && trimmed
            .split('.')
            .all(|segment| !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()))
        && trimmed.split('.').count() <= 3;
    if valid {
        return Ok(());
    }
    Err(ManifestError::RendererRejected {
        renderer: RENDERER.to_owned(),
        message: format!("cluster kube version '{version}' is not a major.minor[.patch] string"),
    })
}

/// Maps a sandboxed-command failure onto the manifest error surface.
fn map_exec_error(err: ExecError) -> ManifestError {
    match err {
        ExecError::Timeout { millis, .. } => ManifestError::RendererTimeout {
            renderer: RENDERER.to_owned(),
            millis,
        },
        ExecError::OutputLimit { stream, limit, .. } => ManifestError::RendererOutputLimit {
            renderer: RENDERER.to_owned(),
            stream: stream.to_owned(),
            limit,
        },
        other => ManifestError::RendererFailed {
            renderer: RENDERER.to_owned(),
            message: other.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::manifest::fake_runner::FakeBinary;
    use crate::manifest::renderer::RendererConfig;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write fixture file");
    }

    fn fixture(root: &Path) {
        write(
            root,
            "chart/Chart.yaml",
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
        );
        write(root, "chart/values.yaml", "replicaCount: 1\n");
        write(root, "chart/values-prod.yaml", "replicaCount: 3\n");
        write(
            root,
            "chart/templates/deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n",
        );
    }

    fn context(root: &Path, options: HelmOptions) -> RenderContext {
        RenderContext::new(root)
            .with_source_path("chart")
            .with_app("ferriscd-system", "demo")
            .with_destination_namespace("payments")
            .with_kube_version("1.35.0")
            .with_renderer(RendererConfig::Helm(options))
    }

    fn options_with(binary: &FakeBinary) -> HelmOptions {
        HelmOptions {
            binary: Some(binary.path().to_path_buf()),
            value_files: vec!["values-prod.yaml".to_owned()],
            inline_values: Some("replicaCount: 5\n".to_owned()),
            set: vec!["image.tag=1.28".to_owned()],
            set_string: vec!["feature.flag=true".to_owned()],
            ..HelmOptions::default()
        }
    }

    #[tokio::test]
    async fn value_file_escaping_the_checkout_is_rejected_before_helm_runs() {
        let base = TempDir::new().expect("tempdir");
        let root = base.path().join("repo");
        fs::create_dir_all(&root).expect("create repo root");
        fixture(&root);
        write(base.path(), "secret.yaml", "password: hunter2\n");

        let fake = FakeBinary::new(
            "helm",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: chart-config\n",
        );
        let options = HelmOptions {
            binary: Some(fake.path().to_path_buf()),
            value_files: vec!["../../secret.yaml".to_owned()],
            ..HelmOptions::default()
        };
        let err = HelmRenderer::new(options.clone())
            .render(&context(&root, options))
            .await
            .expect_err("escaping value file must be rejected");

        match &err {
            ManifestError::UnsafeReference {
                field, reference, ..
            } => {
                assert_eq!(field, "valueFiles");
                assert_eq!(reference, "../../secret.yaml");
            }
            other => panic!("expected UnsafeReference, got {other:?}"),
        }
        assert_eq!(
            fake.invocations(),
            0,
            "helm must never be spawned for a rejected value file"
        );
        assert!(!err.to_string().contains("hunter2"), "{err}");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn remote_value_file_url_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);

        let options = HelmOptions {
            binary: Some(temp.path().join("helm-not-installed")),
            value_files: vec!["https://example.com/values.yaml".to_owned()],
            ..HelmOptions::default()
        };
        let err = HelmRenderer::new(options.clone())
            .render(&context(root, options))
            .await
            .expect_err("remote value file must be rejected");
        assert!(
            matches!(err, ManifestError::UnsafeReference { .. }),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn crds_are_omitted_by_default_and_included_only_on_request() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let fake = FakeBinary::helm_crd_conditional("helm");

        let default_options = HelmOptions {
            binary: Some(fake.path().to_path_buf()),
            ..HelmOptions::default()
        };
        let files = HelmRenderer::new(default_options.clone())
            .render(&context(root, default_options.clone()))
            .await
            .expect("render without CRDs");
        assert_eq!(files.len(), 1);
        assert!(files[0].contents.contains("kind: ConfigMap"));
        assert!(
            !files[0].contents.contains("CustomResourceDefinition"),
            "crds/ must not be rendered unless includeCRDs is true: {}",
            files[0].contents
        );

        let include = HelmOptions {
            include_crds: true,
            ..default_options
        };
        let files = HelmRenderer::new(include.clone())
            .render(&context(root, include))
            .await
            .expect("render with CRDs");
        assert!(
            files[0].contents.contains("kind: CustomResourceDefinition"),
            "--include-crds must render the chart CRDs: {}",
            files[0].contents
        );

        // The rendered output is exactly what the parser sees: it must still be valid manifests.
        let resources = crate::manifest::renderer::parse_and_normalize(files)
            .await
            .expect("CRD-bearing output must normalize");
        assert!(
            resources
                .iter()
                .any(|resource| resource.gvk.kind == "CustomResourceDefinition"),
            "{:?}",
            resources
                .iter()
                .map(|resource| resource.key.canonical())
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn template_argv_carries_namespace_kube_version_values_and_sets() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let fake = FakeBinary::new(
            "helm",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: chart-config\n",
        );
        let options = options_with(&fake);

        let files = HelmRenderer::new(options.clone())
            .render(&context(root, options))
            .await
            .expect("render");
        assert_eq!(files[0].source_file, "helm:chart");

        let args = fake.recorded_args();
        assert_eq!(args[0], "template");
        assert_eq!(
            args[1], "demo",
            "the Application name is the default release"
        );
        assert!(args[2].ends_with("/chart"), "{args:?}");
        assert!(has_pair(&args, "--namespace", "payments"), "{args:?}");
        assert!(has_pair(&args, "--kube-version", "1.35.0"), "{args:?}");

        let values: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                *index > 0 && args.get(index - 1).map(String::as_str) == Some("--values")
            })
            .map(|(_, arg)| arg)
            .collect();
        assert_eq!(values.len(), 2, "value file + inline values: {args:?}");
        assert!(values[0].ends_with("values-prod.yaml"), "{args:?}");
        assert!(
            values[1].contains("ferriscd-helm-") && values[1].ends_with("values.yaml"),
            "inline values must be written to scratch space: {args:?}"
        );
        assert!(has_pair(&args, "--set", "image.tag=1.28"), "{args:?}");
        assert!(
            has_pair(&args, "--set-string", "feature.flag=true"),
            "{args:?}"
        );
        assert!(
            args.iter().any(|arg| arg == "--no-hooks"),
            "chart hooks must never enter the managed inventory: {args:?}"
        );
        assert!(
            !args.iter().any(|arg| arg == "--include-crds"),
            "--include-crds is opt-in: {args:?}"
        );
    }

    /// Finding M4: a chart's `helm.sh/hook` Job must not appear in the rendered bundle (it would
    /// otherwise be applied, diffed, and pruned like an ordinary workload).
    #[tokio::test]
    async fn chart_hooks_are_excluded_from_the_rendered_bundle() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let fake = FakeBinary::helm_hook_conditional("helm");

        // Non-vacuity: the fake really does emit the hook Job when `--no-hooks` is absent, so the
        // absence below is caused by the flag and not by a fixture that never produced a Job.
        let raw = crate::manifest::exec::SandboxedCommand::new(fake.path().as_os_str().to_owned())
            .args(["template", "demo", "."])
            .current_dir(root.join("chart"))
            .run()
            .await
            .expect("fake helm without --no-hooks");
        assert!(raw.stdout.contains("kind: Job"), "{}", raw.stdout);

        let options = HelmOptions {
            binary: Some(fake.path().to_path_buf()),
            ..HelmOptions::default()
        };
        let files = HelmRenderer::new(options.clone())
            .render(&context(root, options))
            .await
            .expect("render");
        assert!(
            !files[0].contents.contains("kind: Job"),
            "a hook Job must not reach the pipeline: {}",
            files[0].contents
        );
        assert!(
            files[0].contents.contains("kind: ConfigMap"),
            "{}",
            files[0].contents
        );

        let resources = crate::manifest::renderer::parse_and_normalize(files)
            .await
            .expect("normalize");
        assert!(
            resources.iter().all(|resource| resource.gvk.kind != "Job"),
            "hook resources must never enter managed inventory: {:?}",
            resources
                .iter()
                .map(|resource| resource.key.canonical())
                .collect::<Vec<_>>()
        );
        assert!(
            fake.recorded_args().iter().any(|arg| arg == "--no-hooks"),
            "--no-hooks must be on the real argv: {:?}",
            fake.recorded_args()
        );
    }

    /// Finding M3: an empty discovered kube version must fail loudly, not silently render with
    /// helm's compiled-in `.Capabilities.KubeVersion`.
    #[tokio::test]
    async fn an_empty_kube_version_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let fake = FakeBinary::new(
            "helm",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: chart-config\n",
        );
        let options = HelmOptions {
            binary: Some(fake.path().to_path_buf()),
            ..HelmOptions::default()
        };
        let mut ctx = context(root, options.clone());
        ctx.cluster_kube_version = "   ".to_owned();

        let err = HelmRenderer::new(options)
            .render(&ctx)
            .await
            .expect_err("an empty kube version must be rejected");
        assert!(
            matches!(err, ManifestError::RendererRejected { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("kube version"), "{err}");
        assert_eq!(
            fake.invocations(),
            0,
            "helm must never be spawned without --kube-version"
        );

        // The same context with a discovered version renders.
        let ok = context(
            root,
            HelmOptions {
                binary: Some(fake.path().to_path_buf()),
                ..HelmOptions::default()
            },
        );
        HelmRenderer::new(HelmOptions {
            binary: Some(fake.path().to_path_buf()),
            ..HelmOptions::default()
        })
        .render(&ok)
        .await
        .expect("a discovered kube version renders");
        assert_eq!(fake.invocations(), 1);
    }

    fn has_pair(args: &[String], flag: &str, value: &str) -> bool {
        args.windows(2)
            .any(|window| window[0] == flag && window[1] == value)
    }

    #[tokio::test]
    async fn flag_shaped_release_names_and_namespaces_are_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let fake = FakeBinary::new(
            "helm",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        );

        // A release name that would be parsed as a Helm flag (e.g. a post-renderer hook).
        let options = HelmOptions {
            release_name: Some("--post-renderer=/tmp/evil.sh".to_owned()),
            binary: Some(fake.path().to_path_buf()),
            ..HelmOptions::default()
        };
        let err = HelmRenderer::new(options.clone())
            .render(&context(root, options))
            .await
            .expect_err("flag-shaped release name must be rejected");
        assert!(err.to_string().contains("release name"), "{err}");

        // A namespace that would be parsed as a flag.
        let mut context_with_bad_namespace = context(
            root,
            HelmOptions {
                binary: Some(fake.path().to_path_buf()),
                ..HelmOptions::default()
            },
        );
        context_with_bad_namespace.destination_namespace = "--set=x".to_owned();
        let err = HelmRenderer::new(HelmOptions {
            binary: Some(fake.path().to_path_buf()),
            ..HelmOptions::default()
        })
        .render(&context_with_bad_namespace)
        .await
        .expect_err("flag-shaped namespace must be rejected");
        assert!(err.to_string().contains("namespace"), "{err}");

        assert_eq!(fake.invocations(), 0, "nothing may be spawned");
    }

    #[test]
    fn release_name_and_kube_version_validation() {
        for valid in ["demo", "demo-app", "demo.app", "a", "app-1"] {
            assert!(
                validate_release_name(valid).is_ok(),
                "{valid} must be valid"
            );
        }
        for invalid in ["", "-demo", ".demo", "demo-", "Demo", "demo_app", "--set=x"] {
            assert!(
                validate_release_name(invalid).is_err(),
                "{invalid} must be rejected"
            );
        }

        for valid in ["1.35", "1.35.0", "v1.35.0"] {
            assert!(
                validate_kube_version(valid).is_ok(),
                "{valid} must be accepted"
            );
        }
        for invalid in ["", "v", "1..0", "1.35.0.1", "--help", "latest"] {
            assert!(
                validate_kube_version(invalid).is_err(),
                "{invalid} must be rejected"
            );
        }
    }

    #[test]
    fn inline_values_are_written_to_scratch_not_argv() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);

        let prepared = prepare(
            root,
            "chart",
            &HelmOptions {
                inline_values: Some("password: hunter2\n".to_owned()),
                ..HelmOptions::default()
            },
        )
        .expect("prepare");
        let values_file = prepared
            .inline_values_file
            .clone()
            .expect("scratch values file");
        assert!(
            !values_file.starts_with(std::fs::canonicalize(root).expect("canonical root")),
            "inline values must never be written into the checkout"
        );
        assert_eq!(
            fs::read_to_string(&values_file).expect("read scratch values"),
            "password: hunter2\n"
        );

        let args = template_args(
            &context(root, HelmOptions::default()),
            &HelmOptions::default(),
            &prepared,
        )
        .expect("args");
        assert!(
            !args
                .iter()
                .any(|arg| arg.to_string_lossy().contains("hunter2")),
            "secret values must never appear in argv: {args:?}"
        );
    }

    #[test]
    fn chart_directory_without_chart_yaml_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(
            root,
            "manifests/configmap.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        );

        let err = prepare(root, "manifests", &HelmOptions::default())
            .expect_err("missing Chart.yaml must fail");
        assert!(err.to_string().contains("Chart.yaml"), "{err}");
    }

    #[test]
    fn missing_value_file_is_reported() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);

        let err = prepare(
            root,
            "chart",
            &HelmOptions {
                value_files: vec!["values-missing.yaml".to_owned()],
                ..HelmOptions::default()
            },
        )
        .expect_err("missing values file must fail");
        assert!(matches!(err, ManifestError::NotFound { .. }), "{err:?}");
    }

    #[test]
    fn release_name_falls_back_to_ferriscd_when_the_application_name_is_empty() {
        let prepared = PreparedHelm {
            chart_dir: PathBuf::from("/repo/chart"),
            relative_chart: "chart".to_owned(),
            value_files: Vec::new(),
            inline_values_file: None,
            _scratch: tempfile::tempdir().expect("scratch"),
        };
        let ctx = RenderContext::new("/repo")
            .with_source_path("chart")
            .with_kube_version("1.35.0");
        let args = template_args(&ctx, &HelmOptions::default(), &prepared).expect("args");
        assert_eq!(args[1], OsString::from(DEFAULT_RELEASE_NAME));
    }
}
