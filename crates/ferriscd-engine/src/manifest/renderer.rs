//! Uniform manifest-renderer seam: auto-detection, explicit selection, and the pipeline from
//! raw renderer output back into Phase 03/04 normalization.
//!
//! Every renderer — [`PlainYamlRenderer`], [`KustomizeRenderer`](super::kustomize),
//! [`HelmRenderer`](super::helm) — returns *raw manifest text*. Nothing is normalized inside a
//! renderer: the bytes always flow through [`yaml::parse_file`] (YAML 1.2 budgets, `v1/List`
//! flattening, `apiVersion`/`kind` validation) and [`normalize::normalize`] (`status` stripping,
//! server-metadata stripping, `Secret.stringData` → base64 `.data`, duplicate GKNN rejection).
//!
//! That single funnel is the point of the trait: an ecosystem renderer can be added without ever
//! touching the parser, the normalizer, the diff engine, or the controller, and it is impossible
//! for a renderer to skip a safety step that a plain-YAML bundle goes through.
//!
//! ```text
//! RenderContext ──► ManifestRenderer::render ──► Vec<ManifestFile> (raw text)
//!                                                    │
//!                            parse_and_normalize ◄───┘
//!                                     │
//!                                     ▼
//!                          Vec<DesiredResource>
//! ```
//!
//! Blocking work (directory detection, plain-YAML reading, kustomization scanning, Helm value-file
//! validation) runs inside [`tokio::task::spawn_blocking`]; external binaries run through
//! [`SandboxedCommand`](super::exec::SandboxedCommand), which never blocks a Tokio worker.

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use ferriscd_crd::{Application, RendererSpec};

use super::error::ManifestError;
use super::helm::{HelmOptions, HelmRenderer};
use super::kustomize::{KustomizeOptions, KustomizeRenderer};
use super::loader::{self, ManifestFile, ManifestLoaderConfig};
use super::normalize;
use super::types::DesiredResource;
use super::yaml;

/// Chart marker file that selects the Helm renderer during auto-detection.
pub const CHART_FILE: &str = "Chart.yaml";

/// Kustomization marker files (any of them) that select the Kustomize renderer.
pub const KUSTOMIZATION_FILES: [&str; 3] =
    ["kustomization.yaml", "kustomization.yml", "Kustomization"];

/// Renderer selected for one source path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RendererKind {
    /// Literal multi-document YAML/JSON manifests (or a single manifest file).
    PlainYaml,
    /// `kustomize build` over a kustomization directory.
    Kustomize,
    /// `helm template` over a chart directory.
    Helm,
}

impl RendererKind {
    /// Stable lowercase name used in errors and log fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlainYaml => "plainYaml",
            Self::Kustomize => "kustomize",
            Self::Helm => "helm",
        }
    }
}

impl fmt::Display for RendererKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options for [`PlainYamlRenderer`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlainYamlOptions {
    /// Descend into sub-directories of the source path (Phase 03 default: `true`).
    pub recursive: bool,
}

impl Default for PlainYamlOptions {
    fn default() -> Self {
        Self { recursive: true }
    }
}

/// Renderer selection plus per-renderer configuration.
///
/// Mirrors [`ferriscd_crd::RendererSpec`] and adds the engine-only knobs that the `v1alpha1` CRD
/// does not expose yet (Kustomize `namePrefix`/`nameSuffix`, Helm inline values and `--set`
/// pairs, and test/operator overrides for the renderer binary path, deadline, and output cap).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RendererConfig {
    /// Detect the renderer from the files present in the source path.
    #[default]
    Auto,
    /// Literal YAML/JSON manifests.
    PlainYaml(PlainYamlOptions),
    /// `kustomize build` with the remote-reference guard applied first.
    Kustomize(KustomizeOptions),
    /// `helm template` in strict offline mode.
    Helm(HelmOptions),
}

impl RendererConfig {
    /// Builds the engine configuration from the CRD's `spec.source.renderer`.
    ///
    /// This is the single extension point for future CRD fields: everything the engine supports
    /// is expressible here, whether or not `v1alpha1` exposes it yet.
    #[must_use]
    pub fn from_crd(spec: &RendererSpec) -> Self {
        match spec {
            RendererSpec::Auto(_) => Self::Auto,
            RendererSpec::PlainYaml(renderer) => Self::PlainYaml(PlainYamlOptions {
                recursive: renderer.recursive,
            }),
            RendererSpec::Kustomize(renderer) => {
                Self::Kustomize(KustomizeOptions::from_crd(renderer))
            }
            RendererSpec::Helm(renderer) => Self::Helm(HelmOptions::from_crd(renderer)),
        }
    }

    /// Unambiguous, length-prefixed canonical form used by the render cache key.
    ///
    /// Fields are encoded as `<byte-length>:<value>;` so no combination of user-controlled values
    /// (image names containing `=`, paths containing `,`, prefix/suffix containing `}`) can make
    /// two different configurations encode identically.
    ///
    /// Crate-private on purpose: the string embeds Helm inline `values` and `--set`/`--set-string`
    /// pairs verbatim, so it is a credential pre-image rather than loggable text (finding H1).
    /// Outside the engine a key comes from [`super::cache::RenderCacheKey::from_context`], whose
    /// `Debug` prints a digest of this value instead.
    #[must_use]
    pub(crate) fn canonical(&self) -> String {
        let mut out = String::new();
        match self {
            Self::Auto => encode_fields(&mut out, &["auto"]),
            Self::PlainYaml(options) => encode_fields(
                &mut out,
                &["plainYaml", if options.recursive { "1" } else { "0" }],
            ),
            Self::Kustomize(options) => {
                let images: Vec<&str> = options.images.iter().map(String::as_str).collect();
                let mut fields = vec![
                    "kustomize",
                    options.kustomization_path.as_deref().unwrap_or(""),
                    options.name_prefix.as_deref().unwrap_or(""),
                    options.name_suffix.as_deref().unwrap_or(""),
                ];
                fields.extend(images);
                encode_fields(&mut out, &fields);
            }
            Self::Helm(options) => {
                let values: Vec<&str> = options.value_files.iter().map(String::as_str).collect();
                let set: Vec<&str> = options.set.iter().map(String::as_str).collect();
                let set_string: Vec<&str> = options.set_string.iter().map(String::as_str).collect();
                let mut fields = vec![
                    "helm",
                    options.release_name.as_deref().unwrap_or(""),
                    options.inline_values.as_deref().unwrap_or(""),
                    if options.include_crds { "1" } else { "0" },
                ];
                fields.extend(values);
                fields.push("\u{1}set");
                fields.extend(set);
                fields.push("\u{1}set-string");
                fields.extend(set_string);
                encode_fields(&mut out, &fields);
            }
        }
        out
    }
}

/// Operator overrides for the external renderer binaries.
///
/// A renderer's [`RendererConfig`] is derived from the CRD and can never name a binary, so this is
/// the only way to point a deployment (or a hermetic test) at a specific `kustomize`/`helm`
/// installation. The override is deliberately **excluded** from [`RendererConfig::canonical`] and
/// therefore from the render cache key: which binary runs cannot change *what* a commit renders to.
///
/// Every configured binary must be an absolute path or a bare `PATH` name; the sandbox rejects
/// relative paths outright (a repository-provided `./kustomize` can never be executed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RendererBinaries {
    /// Overrides the `kustomize` binary.
    pub kustomize: Option<PathBuf>,
    /// Overrides the `helm` binary.
    pub helm: Option<PathBuf>,
}

impl RendererBinaries {
    /// Returns `true` when neither binary is overridden.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kustomize.is_none() && self.helm.is_none()
    }
}

/// Everything one render needs, and nothing about the cluster.
///
/// The `repo_url`/`commit_sha`/`app_namespace`/`app_name`/`destination_namespace`/
/// `cluster_kube_version` fields exist because rendered output depends on all of them (Helm
/// `.Release.Name`/`.Release.Namespace`, `.Capabilities.KubeVersion`, and per-app kustomize
/// configuration). [`super::cache::RenderCacheKey`] hashes exactly this tuple.
#[derive(Clone, PartialEq, Eq)]
pub struct RenderContext {
    /// Root of the immutable, symlink-sanitized checkout.
    pub root_dir: PathBuf,
    /// Repository URL the checkout came from (part of the render cache key).
    pub repo_url: String,
    /// Resolved commit SHA of the checkout (part of the render cache key).
    pub commit_sha: String,
    /// `spec.source.git.path`: the sub-path to render.
    pub source_path: String,
    /// Namespace of the `Application` object (part of the render cache key).
    pub app_namespace: String,
    /// Name of the `Application` object; the default Helm release name.
    pub app_name: String,
    /// `spec.destination.namespace`: passed to Helm as `--namespace`.
    pub destination_namespace: String,
    /// Cluster server version (e.g. `1.35.0`) passed to Helm as `--kube-version`.
    pub cluster_kube_version: String,
    /// Renderer selection and configuration.
    pub renderer: RendererConfig,
    /// File-count/byte budgets used by the plain-YAML path (and therefore by every auto-detected
    /// plain bundle). An *explicit* `plainYaml` selection owns `recursive`; the budgets always
    /// come from here.
    pub loader: ManifestLoaderConfig,
    /// Optional `kustomize`/`helm` binary overrides (never part of the render cache key).
    pub binaries: RendererBinaries,
}

impl fmt::Debug for RenderContext {
    /// Redacts the repository URL (which may embed credentials via
    /// `https://user:token@host/...`); renderer options redact themselves.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderContext")
            .field("root_dir", &self.root_dir)
            .field("repo_url", &RedactedUrl::new(&self.repo_url))
            .field("commit_sha", &self.commit_sha)
            .field("source_path", &self.source_path)
            .field("app_namespace", &self.app_namespace)
            .field("app_name", &self.app_name)
            .field("destination_namespace", &self.destination_namespace)
            .field("cluster_kube_version", &self.cluster_kube_version)
            .field("renderer", &self.renderer)
            .field("loader", &self.loader)
            .field("binaries", &self.binaries)
            .finish()
    }
}

impl RenderContext {
    /// Creates a context for `root_dir` with everything empty and [`RendererConfig::Auto`].
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>) -> Self {
        Self {
            root_dir: root_dir.into(),
            repo_url: String::new(),
            commit_sha: String::new(),
            source_path: String::new(),
            app_namespace: String::new(),
            app_name: String::new(),
            destination_namespace: String::new(),
            cluster_kube_version: String::new(),
            renderer: RendererConfig::Auto,
            loader: ManifestLoaderConfig::default(),
            binaries: RendererBinaries::default(),
        }
    }

    /// Builds a context from an `Application` CR and the immutable checkout of its commit.
    ///
    /// This is the seam the controller uses (see `ferriscd-controller`'s `fetch_desired`): no
    /// controller code needs to know about renderers, detection order, or cache keys — it resolves
    /// the revision, leases the checkout, discovers the cluster version, and hands all three here.
    #[must_use]
    pub fn for_application(
        root_dir: impl Into<PathBuf>,
        app: &Application,
        cluster_kube_version: &str,
    ) -> Self {
        Self {
            root_dir: root_dir.into(),
            repo_url: app.spec.source.repo_url().to_owned(),
            commit_sha: String::new(),
            source_path: app.spec.source.source_path().to_owned(),
            app_namespace: app.metadata.namespace.clone().unwrap_or_default(),
            app_name: app.metadata.name.clone().unwrap_or_default(),
            destination_namespace: app.spec.destination.namespace.clone(),
            cluster_kube_version: cluster_kube_version.to_owned(),
            renderer: RendererConfig::from_crd(&app.spec.source.renderer),
            loader: ManifestLoaderConfig::default(),
            binaries: RendererBinaries::default(),
        }
    }

    /// Sets the resolved commit SHA of the checkout.
    #[must_use]
    pub fn with_commit_sha(mut self, commit_sha: impl Into<String>) -> Self {
        self.commit_sha = commit_sha.into();
        self
    }

    /// Sets the repository URL (part of the render cache key).
    #[must_use]
    pub fn with_repo_url(mut self, repo_url: impl Into<String>) -> Self {
        self.repo_url = repo_url.into();
        self
    }

    /// Sets the source sub-path to render.
    #[must_use]
    pub fn with_source_path(mut self, source_path: impl Into<String>) -> Self {
        self.source_path = source_path.into();
        self
    }

    /// Sets the `Application` namespace and name.
    #[must_use]
    pub fn with_app(mut self, namespace: impl Into<String>, name: impl Into<String>) -> Self {
        self.app_namespace = namespace.into();
        self.app_name = name.into();
        self
    }

    /// Sets the destination namespace.
    #[must_use]
    pub fn with_destination_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.destination_namespace = namespace.into();
        self
    }

    /// Sets the cluster server version used for Helm capabilities.
    #[must_use]
    pub fn with_kube_version(mut self, version: impl Into<String>) -> Self {
        self.cluster_kube_version = version.into();
        self
    }

    /// Sets the renderer selection.
    #[must_use]
    pub fn with_renderer(mut self, renderer: RendererConfig) -> Self {
        self.renderer = renderer;
        self
    }

    /// Sets the plain-YAML loader budgets (file count, total bytes, recursion default).
    #[must_use]
    pub fn with_loader_config(mut self, loader: ManifestLoaderConfig) -> Self {
        self.loader = loader;
        self
    }

    /// Sets the external renderer binary overrides (excluded from the render cache key).
    #[must_use]
    pub fn with_binaries(mut self, binaries: RendererBinaries) -> Self {
        self.binaries = binaries;
        self
    }
}

/// Boxed `Send` future returned by [`ManifestRenderer::render`].
pub type RenderFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ManifestError>> + Send + 'a>>;

/// One manifest renderer: raw text in, raw manifest text out.
///
/// Implementations must **not** parse, normalize, or otherwise interpret Kubernetes semantics;
/// they only produce [`ManifestFile`]s. The `source_file` a renderer reports is a synthetic label
/// (e.g. `kustomize:apps/prod`) that appears verbatim in parse/validation errors.
pub trait ManifestRenderer: Send + Sync {
    /// Which renderer this is.
    fn kind(&self) -> RendererKind;

    /// Produces the raw manifest text for `ctx`.
    fn render<'a>(&'a self, ctx: &'a RenderContext) -> RenderFuture<'a, Vec<ManifestFile>>;
}

/// Phase 03's plain YAML/JSON loader behind the [`ManifestRenderer`] seam.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlainYamlRenderer {
    options: PlainYamlOptions,
}

impl PlainYamlRenderer {
    /// Creates a plain YAML renderer.
    #[must_use]
    pub fn new(options: PlainYamlOptions) -> Self {
        Self { options }
    }
}

impl ManifestRenderer for PlainYamlRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::PlainYaml
    }

    fn render<'a>(&'a self, ctx: &'a RenderContext) -> RenderFuture<'a, Vec<ManifestFile>> {
        Box::pin(async move {
            let root = ctx.root_dir.clone();
            let source_path = ctx.source_path.clone();
            // Budgets come from the caller's loader configuration; recursion is owned by the
            // renderer selection (an explicit `plainYaml.recursive`).
            let config = ctx.loader.clone().with_recursive(self.options.recursive);
            let files =
                tokio::task::spawn_blocking(move || loader::load(&root, &source_path, &config))
                    .await
                    .map_err(|join_err| task_failed(RendererKind::PlainYaml, join_err))??;
            Ok(files)
        })
    }
}

/// Detects the renderer for `source_path` inside `root`.
///
/// Precedence is fixed and documented: `Chart.yaml` → Helm, then
/// `kustomization.yaml`/`kustomization.yml`/`Kustomization` → Kustomize, else plain YAML. A single
/// manifest *file* is always plain YAML, because neither `kustomize` nor `helm` can render one.
///
/// This performs filesystem metadata reads, so callers on a Tokio worker must wrap it in
/// [`tokio::task::spawn_blocking`] (the async helpers in this module already do).
///
/// # Errors
///
/// Returns [`ManifestError::NotFound`] for a missing path and [`ManifestError::PathEscape`] when
/// the path (or a marker file it resolves through) escapes `root`.
pub fn detect_renderer(root: &Path, source_path: &str) -> Result<RendererKind, ManifestError> {
    let canonical_root = canonical_root(root)?;
    let target = resolve_source_path(&canonical_root, source_path)?;

    if target.is_file() {
        return Ok(RendererKind::PlainYaml);
    }
    if !target.is_dir() {
        return Err(ManifestError::InvalidPath {
            path: target.display().to_string(),
            reason: "source path must be a regular file or a directory".to_owned(),
        });
    }

    if contained_file(&canonical_root, &target.join(CHART_FILE))?.is_some() {
        return Ok(RendererKind::Helm);
    }
    for name in KUSTOMIZATION_FILES {
        if contained_file(&canonical_root, &target.join(name))?.is_some() {
            return Ok(RendererKind::Kustomize);
        }
    }

    Ok(RendererKind::PlainYaml)
}

/// Renders `ctx` with the detected or explicitly selected renderer, returning raw manifest text.
///
/// # Errors
///
/// Propagates detection, sandboxing, and renderer failures. Output has **not** been parsed yet:
/// use [`render_desired`] unless you need the raw text.
pub async fn render(ctx: &RenderContext) -> Result<Vec<ManifestFile>, ManifestError> {
    let renderer = resolve(ctx).await?;
    renderer.render(ctx).await
}

/// Renders `ctx` and runs the result through Phase 03 parsing and Phase 04 normalization.
///
/// # Errors
///
/// Propagates renderer failures, YAML budget breaches, manifest validation failures, malformed
/// `Secret` fields, and duplicate GKNN keys — identically for every renderer.
pub async fn render_desired(ctx: &RenderContext) -> Result<Vec<DesiredResource>, ManifestError> {
    let files = render(ctx).await?;
    parse_and_normalize(files).await
}

/// Parses and normalizes rendered manifest text exactly like a plain-YAML bundle (blocking).
///
/// This is the *only* path from renderer output to [`DesiredResource`], which is what guarantees
/// `v1/List` flattening, `Secret.stringData` conversion, `.status` stripping, and duplicate GKNN
/// rejection cannot be bypassed by an ecosystem renderer.
///
/// # Errors
///
/// Returns [`ManifestError::YamlParse`], [`ManifestError::YamlBudget`],
/// [`ManifestError::Validation`], [`ManifestError::Normalization`], and
/// [`ManifestError::DuplicateResourceKey`] exactly as the plain-YAML pipeline does.
pub async fn parse_and_normalize(
    files: Vec<ManifestFile>,
) -> Result<Vec<DesiredResource>, ManifestError> {
    tokio::task::spawn_blocking(move || {
        let mut resources = Vec::new();
        for file in files {
            resources.extend(yaml::parse_file(&file.source_file, &file.contents)?);
        }
        normalize::normalize(resources)
    })
    .await
    .map_err(|join_err| ManifestError::RendererFailed {
        renderer: "manifest".to_owned(),
        message: format!("manifest parsing task failed: {join_err}"),
    })?
}

/// Resolves the renderer for `ctx`, running auto-detection off the async worker when needed.
async fn resolve(ctx: &RenderContext) -> Result<Box<dyn ManifestRenderer>, ManifestError> {
    let kind = match &ctx.renderer {
        RendererConfig::Auto => {
            let root = ctx.root_dir.clone();
            let source_path = ctx.source_path.clone();
            tokio::task::spawn_blocking(move || detect_renderer(&root, &source_path))
                .await
                .map_err(|join_err| ManifestError::RendererFailed {
                    renderer: "auto".to_owned(),
                    message: format!("renderer detection task failed: {join_err}"),
                })??
        }
        RendererConfig::PlainYaml(_) => RendererKind::PlainYaml,
        RendererConfig::Kustomize(_) => RendererKind::Kustomize,
        RendererConfig::Helm(_) => RendererKind::Helm,
    };

    // An explicit selection always wins; auto-detection falls back to the renderer's defaults, and
    // a context-level binary override fills in whatever the selection left unset.
    Ok(match kind {
        RendererKind::PlainYaml => {
            let options = match &ctx.renderer {
                RendererConfig::PlainYaml(options) => *options,
                // Auto-detection carries no plain-YAML options, so it honours the caller's loader
                // configuration instead of hard-coding `recursive: true`.
                _ => PlainYamlOptions {
                    recursive: ctx.loader.recursive,
                },
            };
            Box::new(PlainYamlRenderer::new(options))
        }
        RendererKind::Kustomize => {
            let mut options = match &ctx.renderer {
                RendererConfig::Kustomize(options) => options.clone(),
                _ => KustomizeOptions::default(),
            };
            if options.binary.is_none() {
                options.binary.clone_from(&ctx.binaries.kustomize);
            }
            Box::new(KustomizeRenderer::new(options))
        }
        RendererKind::Helm => {
            let mut options = match &ctx.renderer {
                RendererConfig::Helm(options) => options.clone(),
                _ => HelmOptions::default(),
            };
            if options.binary.is_none() {
                options.binary.clone_from(&ctx.binaries.helm);
            }
            Box::new(HelmRenderer::new(options))
        }
    })
}

/// Maps a blocking-task join failure into a terminal renderer error.
pub(super) fn task_failed(kind: RendererKind, join_err: tokio::task::JoinError) -> ManifestError {
    ManifestError::RendererFailed {
        renderer: kind.as_str().to_owned(),
        message: format!("renderer task failed: {join_err}"),
    }
}

/// A repository URL rendered without any embedded userinfo.
pub(crate) struct RedactedUrl<'a>(&'a str);

impl RedactedUrl<'_> {
    /// Wraps `url` for redacted logging.
    pub(crate) fn new(url: &str) -> RedactedUrl<'_> {
        RedactedUrl(url)
    }
}

impl fmt::Debug for RedactedUrl<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact_repo_url(self.0))
    }
}

/// Replaces the userinfo of `scheme://userinfo@host` with a non-identifying form.
///
/// * `https://robot:s3cr3t-token@example.com/repo.git` → `https://robot:***@example.com/repo.git`
///   (the account name is not a secret; the password never is).
/// * `https://ghp_16C7e42F@example.com/repo.git` → `https://***@example.com/repo.git` — a **bare**
///   userinfo with no colon is not a username, it is a token, because GitHub/GitLab personal
///   access tokens are used exactly that way. Printing it as the "user" leaks the credential.
/// * `ssh://user@host/repo.git` → `ssh://***@host/repo.git` (same rule: no colon, no username to
///   keep).
///
/// Forgetting this is a real leak: repository URLs routinely embed a personal access token, and
/// [`RenderContext`], [`super::cache::RenderCacheKey`], the `AppProject` policy messages
/// (`T12.1`), and the sync refusals (`T12.3` finding M4) all quote a repository URL in a log line
/// or in `Application.status`, which anyone allowed to read the CR can see.
#[must_use]
pub fn redact_repo_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        // `git@github.com:org/repo.git` is an scp-style remote, not a URL with userinfo.
        return url.to_owned();
    };
    let Some((userinfo, host)) = rest.split_once('@') else {
        return url.to_owned();
    };
    // An `@` inside a path segment (`https://example.com/team@corp/repo.git`) is not userinfo, so
    // only the first segment may be treated as one.
    if userinfo.contains('/') {
        return url.to_owned();
    }
    let redacted = match userinfo.split_once(':') {
        // Keep the username only when there really is a `user:` and it is not empty.
        Some((user, _password)) if !user.is_empty() => format!("{user}:***"),
        // A bare token, an empty username, or a lone `:`: redact the whole userinfo.
        _ => "***".to_owned(),
    };
    format!("{scheme}://{redacted}@{host}")
}

/// Appends `<byte-length>:<value>;` for every field, making concatenations unambiguous.
pub(crate) fn encode_fields(out: &mut String, fields: &[&str]) {
    for field in fields {
        out.push_str(&field.len().to_string());
        out.push(':');
        out.push_str(field);
        out.push(';');
    }
}

/// Canonicalizes the checkout root.
pub(crate) fn canonical_root(root: &Path) -> Result<PathBuf, ManifestError> {
    canonicalize(root, "canonicalizing checkout root")
}

/// Resolves `path` inside the canonical `root` and proves the result cannot escape it.
pub(crate) fn resolve_source_path(
    root: &Path,
    source_path: &str,
) -> Result<PathBuf, ManifestError> {
    let joined = root.join(source_path);
    let lexical = loader::lexically_normalize(&joined);
    if !lexical.starts_with(root) {
        return Err(ManifestError::PathEscape {
            path: joined.display().to_string(),
            root: root.display().to_string(),
        });
    }
    let canonical = canonicalize(&lexical, "canonicalizing the render source path")?;
    ensure_inside(root, &canonical)
}

/// Resolves `relative` against `base` and proves the result stays inside the canonical `root`.
pub(crate) fn resolve_relative_inside(
    root: &Path,
    base: &Path,
    relative: &str,
) -> Result<PathBuf, ManifestError> {
    let joined = base.join(relative);
    let lexical = loader::lexically_normalize(&joined);
    if !lexical.starts_with(root) {
        return Err(ManifestError::PathEscape {
            path: joined.display().to_string(),
            root: root.display().to_string(),
        });
    }
    let canonical = canonicalize(&lexical, "canonicalizing a renderer reference")?;
    ensure_inside(root, &canonical)
}

/// Canonicalizes `path` if it exists, returning `None` when it does not.
///
/// Used for optional marker files (`Chart.yaml`, `kustomization.yaml`): a marker that escapes the
/// checkout through a symlink is a path-escape error, never a silent "absent".
pub(crate) fn contained_file(root: &Path, path: &Path) -> Result<Option<PathBuf>, ManifestError> {
    let canonical = match std::fs::canonicalize(path) {
        Ok(canonical) => canonical,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ManifestError::Io {
                context: format!("canonicalizing marker file '{}'", path.display()),
                source,
            });
        }
    };
    if !canonical.starts_with(root) {
        return Err(ManifestError::PathEscape {
            path: canonical.display().to_string(),
            root: root.display().to_string(),
        });
    }
    if canonical.is_file() {
        Ok(Some(canonical))
    } else {
        Ok(None)
    }
}

/// Returns `true` when a reference is a remote URL, a protocol-relative or absolute path, or a
/// VCS shorthands (`git::`, `git@`, `github.com/...`).
///
/// Kustomize's `--load-restrictor=LoadRestrictionsRootOnly` does **not** stop these: it only
/// constrains local file loads, so `resources: [https://...]` would be fetched (SSRF) unless it is
/// rejected before the subprocess runs.
#[must_use]
pub(crate) fn is_remote_reference(reference: &str) -> bool {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();

    lower.contains("://")
        || lower.starts_with("git::")
        || lower.starts_with("git@")
        || lower.starts_with("//")
        || lower.starts_with('/')
        || lower.contains("?ref=")
        || lower.contains("?version=")
        || lower.starts_with("github.com/")
        || lower.starts_with("gitlab.com/")
        || lower.starts_with("bitbucket.org/")
        || lower.starts_with("dev.azure.com/")
        || lower.starts_with("ssh.dev.azure.com/")
}

/// Returns the repository-relative, `/`-separated form of `path`.
pub(crate) fn relative_display(root: &Path, path: &Path) -> String {
    let stripped = path.strip_prefix(root).unwrap_or(path);
    let rendered = stripped.to_string_lossy().replace('\\', "/");
    if rendered.is_empty() {
        ".".to_owned()
    } else {
        rendered
    }
}

/// Rejects a canonical path that did not stay inside `root`.
fn ensure_inside(root: &Path, path: &Path) -> Result<PathBuf, ManifestError> {
    if path.starts_with(root) {
        Ok(path.to_path_buf())
    } else {
        Err(ManifestError::PathEscape {
            path: path.display().to_string(),
            root: root.display().to_string(),
        })
    }
}

/// Canonicalizes `path`, mapping a missing path to [`ManifestError::NotFound`].
fn canonicalize(path: &Path, context: &str) -> Result<PathBuf, ManifestError> {
    match std::fs::canonicalize(path) {
        Ok(canonical) => Ok(canonical),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            Err(ManifestError::NotFound {
                path: path.display().to_string(),
            })
        }
        Err(source) => Err(ManifestError::Io {
            context: format!("{context} '{}'", path.display()),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::manifest::fake_runner::FakeBinary;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write fixture file");
    }

    const CONFIGMAP: &str = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app-config\n";

    #[test]
    fn auto_detection_prefers_helm_then_kustomize_then_plain_yaml() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();

        write(root, "plain/configmap.yaml", CONFIGMAP);
        assert_eq!(
            detect_renderer(root, "plain").expect("detect plain"),
            RendererKind::PlainYaml
        );

        write(root, "kz/kustomization.yml", "resources: []\n");
        assert_eq!(
            detect_renderer(root, "kz").expect("detect kustomize"),
            RendererKind::Kustomize
        );

        // `Kustomization` (no extension) is the third recognised spelling.
        write(root, "kz-noext/Kustomization", "resources: []\n");
        assert_eq!(
            detect_renderer(root, "kz-noext").expect("detect kustomize (Kustomization)"),
            RendererKind::Kustomize
        );

        // A chart wins even when a kustomization sits next to it.
        write(
            root,
            "both/Chart.yaml",
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
        );
        write(root, "both/kustomization.yaml", "resources: []\n");
        assert_eq!(
            detect_renderer(root, "both").expect("detect helm"),
            RendererKind::Helm
        );

        // A single manifest file is always plain YAML.
        write(root, "solo.yaml", CONFIGMAP);
        assert_eq!(
            detect_renderer(root, "solo.yaml").expect("detect single file"),
            RendererKind::PlainYaml
        );
    }

    #[test]
    fn auto_detection_rejects_escaping_source_paths() {
        let base = TempDir::new().expect("tempdir");
        let root = base.path().join("repo");
        fs::create_dir_all(&root).expect("create repo root");
        write(
            base.path(),
            "outside/Chart.yaml",
            "apiVersion: v2\nname: x\n",
        );

        let err = detect_renderer(&root, "../outside").expect_err("escape must fail");
        assert!(matches!(err, ManifestError::PathEscape { .. }), "{err:?}");
        assert!(!err.is_retryable());
    }

    #[cfg(unix)]
    #[test]
    fn auto_detection_rejects_a_marker_symlink_that_escapes_the_checkout() {
        let base = TempDir::new().expect("tempdir");
        let root = base.path().join("repo");
        fs::create_dir_all(&root).expect("create repo root");
        write(
            base.path(),
            "outside/Chart.yaml",
            "apiVersion: v2\nname: x\n",
        );
        std::os::unix::fs::symlink("../outside/Chart.yaml", root.join("Chart.yaml"))
            .expect("create escaping symlink");

        let err = detect_renderer(&root, ".").expect_err("escaping marker must fail");
        assert!(matches!(err, ManifestError::PathEscape { .. }), "{err:?}");
    }

    #[tokio::test]
    async fn explicit_selection_overrides_auto_detection() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(
            root,
            "mixed/kustomization.yaml",
            "resources:\n  - configmap.yaml\n",
        );
        write(root, "mixed/configmap.yaml", CONFIGMAP);

        // Auto-detection selects Kustomize for this directory...
        assert_eq!(
            detect_renderer(root, "mixed").expect("detect"),
            RendererKind::Kustomize,
            "a kustomization.yaml must select Kustomize"
        );

        // ...but an explicit plain-YAML selection runs the raw loader instead, so the
        // kustomization file itself is loaded as a (non-manifest) document.
        let explicit = RenderContext::new(root)
            .with_source_path("mixed")
            .with_renderer(RendererConfig::PlainYaml(PlainYamlOptions::default()));
        let files = render(&explicit).await.expect("plain YAML selection");
        let names: Vec<&str> = files.iter().map(|file| file.source_file.as_str()).collect();
        assert_eq!(
            names,
            vec!["mixed/configmap.yaml", "mixed/kustomization.yaml"]
        );

        // That raw loader path is exactly what an explicit plainYaml request means: the
        // kustomization file has no `kind`, so normalization fails instead of silently skipping it.
        let err = render_desired(&explicit)
            .await
            .expect_err("the raw loader must not silently skip kustomization.yaml");
        assert!(
            err.to_string().contains("kustomization.yaml"),
            "the error must name the offending file: {err}"
        );
    }

    #[tokio::test]
    async fn plain_yaml_renderer_honours_the_recursive_flag() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(root, "top.yaml", CONFIGMAP);
        write(root, "nested/deep.yaml", CONFIGMAP);

        let recursive = RenderContext::new(root)
            .with_source_path(".")
            .with_renderer(RendererConfig::PlainYaml(PlainYamlOptions {
                recursive: true,
            }));
        assert_eq!(render(&recursive).await.expect("recursive").len(), 2);

        let flat = RenderContext::new(root)
            .with_source_path(".")
            .with_renderer(RendererConfig::PlainYaml(PlainYamlOptions {
                recursive: false,
            }));
        assert_eq!(render(&flat).await.expect("flat").len(), 1);
    }

    /// Finding M8: the caller's `ManifestLoaderConfig` must reach the renderer, not be replaced by
    /// a hard-coded default inside `PlainYamlRenderer`.
    #[tokio::test]
    async fn context_loader_config_budgets_apply_to_the_plain_path() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(root, "one.yaml", CONFIGMAP);
        write(root, "two.yaml", CONFIGMAP);

        // Auto-detection (no marker files) selects plain YAML; its recursion default comes from
        // the loader configuration, not from a hard-coded `true`.
        let auto = RenderContext::new(root)
            .with_source_path(".")
            .with_loader_config(ManifestLoaderConfig::default().with_max_files(1));
        let err = render(&auto)
            .await
            .expect_err("the caller's file budget must be enforced");
        assert!(
            matches!(err, ManifestError::LimitExceeded { .. }),
            "{err:?}"
        );

        let bounded = RenderContext::new(root)
            .with_source_path(".")
            .with_loader_config(ManifestLoaderConfig::default().with_max_total_bytes(16));
        let err = render(&bounded)
            .await
            .expect_err("the caller's byte budget must be enforced");
        assert!(
            matches!(err, ManifestError::LimitExceeded { .. }),
            "{err:?}"
        );

        // The unbounded default still renders both files, so the assertion above is about the
        // budget and not about the fixture being unreadable.
        let unbounded = RenderContext::new(root).with_source_path(".");
        assert_eq!(render(&unbounded).await.expect("default budgets").len(), 2);
    }

    /// Every renderer must reach the *same* normalized resources for the same YAML text.
    #[tokio::test]
    async fn all_renderers_normalize_identically() {
        const BUNDLE: &str = "\
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Secret
    metadata:
      name: app-secret
      namespace: demo
    stringData:
      token: s3cr3t
  - apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: app
      namespace: demo
    spec:
      replicas: 1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
  namespace: demo
  uid: should-be-stripped
status:
  phase: Running
";

        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(root, "plain/bundle.yaml", BUNDLE);
        write(
            root,
            "chart/Chart.yaml",
            "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
        );
        write(root, "kz/kustomization.yaml", "resources: []\n");

        let helmed = FakeBinary::new("helm", BUNDLE);
        let kustomized = FakeBinary::new("kustomize", BUNDLE);

        let plain = render_desired(
            &RenderContext::new(root)
                .with_source_path("plain")
                .with_renderer(RendererConfig::PlainYaml(PlainYamlOptions::default())),
        )
        .await
        .expect("plain render");

        let kustomize = render_desired(
            &RenderContext::new(root)
                .with_source_path("kz")
                .with_renderer(RendererConfig::Kustomize(KustomizeOptions {
                    binary: Some(kustomized.path().to_path_buf()),
                    ..KustomizeOptions::default()
                })),
        )
        .await
        .expect("kustomize render");

        let helm = render_desired(
            &RenderContext::new(root)
                .with_app("ferriscd-system", "demo")
                .with_destination_namespace("demo")
                .with_kube_version("1.35.0")
                .with_source_path("chart")
                .with_renderer(RendererConfig::Helm(HelmOptions {
                    binary: Some(helmed.path().to_path_buf()),
                    ..HelmOptions::default()
                })),
        )
        .await
        .expect("helm render");

        fn shape(resources: &[DesiredResource]) -> Vec<String> {
            let mut rows: Vec<String> = resources
                .iter()
                .map(|resource| {
                    let token = resource
                        .object
                        .data
                        .get("data")
                        .and_then(serde_json::Value::as_object)
                        .and_then(|map| map.get("token"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                    format!(
                        "{}|status_present={}|uid_present={}|token={token}",
                        resource.key.canonical(),
                        resource.object.data.get("status").is_some(),
                        resource.object.metadata.uid.is_some(),
                    )
                })
                .collect();
            rows.sort();
            rows
        }

        let rows = shape(&plain);
        assert_eq!(rows.len(), 3, "v1/List must be flattened: {rows:?}");
        assert_eq!(
            rows,
            shape(&kustomize),
            "kustomize output must normalize identically"
        );
        assert_eq!(rows, shape(&helm), "helm output must normalize identically");
        assert!(
            rows.iter()
                .any(|row| row.contains("/Secret/demo/app-secret")),
            "the List item must survive flattening: {rows:?}"
        );
        assert!(
            rows.iter().any(|row| row.contains("token=czNjcjN0")),
            "stringData must be base64-encoded into .data: {rows:?}"
        );
        assert!(
            rows.iter().all(|row| row.contains("status_present=false")),
            ".status must be stripped for every renderer: {rows:?}"
        );
        assert!(
            rows.iter().all(|row| row.contains("uid_present=false")),
            "server-set metadata must be stripped for every renderer: {rows:?}"
        );
    }

    /// The trap: a renderer must not be able to smuggle a duplicate GKNN past the normalizer.
    #[tokio::test]
    async fn rendered_duplicate_keys_are_rejected() {
        const DUPLICATE: &str = "\
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
";
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(root, "kz/kustomization.yaml", "resources: []\n");
        let fake = FakeBinary::new("kustomize", DUPLICATE);

        let err = render_desired(
            &RenderContext::new(root)
                .with_source_path("kz")
                .with_renderer(RendererConfig::Kustomize(KustomizeOptions {
                    binary: Some(fake.path().to_path_buf()),
                    ..KustomizeOptions::default()
                })),
        )
        .await
        .expect_err("duplicate GKNN must be rejected for rendered output");

        assert!(
            matches!(err, ManifestError::DuplicateResourceKey { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("kustomize:kz"), "{err}");
    }

    /// Renders the committed `examples/kustomize` and `examples/helm` bundles with the **real**
    /// binaries. `#[ignore]`d so `make gate` stays hermetic; run it explicitly when the tools are
    /// installed to catch argv drift (`cargo test -p ferriscd-engine --lib -- --ignored examples`).
    #[tokio::test]
    #[ignore = "requires the real kustomize v5 and helm v4 binaries on PATH"]
    async fn committed_examples_render_with_the_real_binaries() {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples")
            .canonicalize()
            .expect("resolve examples directory");

        let kustomize = RenderContext::new(examples.join("kustomize"))
            .with_repo_url("https://example.com/ferris-cd/examples.git")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_source_path("overlays/prod")
            .with_destination_namespace("ferriscd-render")
            .with_kube_version("1.35.0")
            .with_renderer(RendererConfig::Kustomize(KustomizeOptions::default()));
        let rendered = render_desired(&kustomize)
            .await
            .expect("kustomize must render the example overlay");
        assert!(
            rendered
                .iter()
                .any(|resource| resource.gvk.kind == "Deployment")
        );

        // The scratch post-build overlay must work against the real `kustomize` too.
        let prefixed = RenderContext {
            renderer: RendererConfig::Kustomize(KustomizeOptions {
                name_prefix: Some("prod-".to_owned()),
                images: vec!["nginx=nginx:1.27-alpine".to_owned()],
                ..KustomizeOptions::default()
            }),
            ..kustomize
        };
        let rendered = render_desired(&prefixed)
            .await
            .expect("kustomize must apply the scratch overlay");
        let deployment = rendered
            .iter()
            .find(|resource| resource.gvk.kind == "Deployment")
            .expect("deployment");
        assert_eq!(deployment.key.name, "prod-render-app");

        let helm = RenderContext::new(examples.join("helm"))
            .with_repo_url("https://example.com/ferris-cd/examples.git")
            .with_commit_sha("0123456789abcdef0123456789abcdef01234567")
            .with_source_path(".")
            .with_app("ferriscd-system", "render-demo")
            .with_destination_namespace("ferriscd-render-helm")
            .with_kube_version("1.35.0")
            .with_renderer(RendererConfig::Helm(HelmOptions {
                value_files: vec!["values-prod.yaml".to_owned()],
                inline_values: Some("replicaCount: 2\n".to_owned()),
                ..HelmOptions::default()
            }));
        let rendered = render_desired(&helm)
            .await
            .expect("helm must render the example chart");
        assert!(
            rendered
                .iter()
                .all(|resource| resource.gvk.kind != "CustomResourceDefinition"),
            "crds/ must stay out of the bundle by default"
        );
        let deployment = rendered
            .iter()
            .find(|resource| resource.gvk.kind == "Deployment")
            .expect("deployment");
        assert_eq!(
            deployment
                .object
                .data
                .pointer("/spec/replicas")
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
    }

    /// The controller seam: an `Application` CR plus its checkout describes a render.
    #[test]
    fn for_application_maps_the_crd_onto_a_render_context() {
        let app: ferriscd_crd::Application = serde_json::from_value(serde_json::json!({
            "apiVersion": "ferriscd.io/v1alpha1",
            "kind": "Application",
            "metadata": { "name": "demo", "namespace": "ferriscd-system" },
            "spec": {
                "project": "default",
                "source": {
                    "git": {
                        "repoURL": "https://example.com/repo.git",
                        "targetRevision": "main",
                        "path": "apps/prod"
                    },
                    "renderer": {
                        "helm": {
                            "releaseName": "prod",
                            "valueFiles": ["values-prod.yaml"],
                            "includeCRDs": true
                        }
                    }
                },
                "destination": { "cluster": "in-cluster", "namespace": "payments" }
            }
        }))
        .expect("valid Application fixture");

        let ctx = RenderContext::for_application("/repo", &app, "1.35.0");
        assert_eq!(ctx.app_namespace, "ferriscd-system");
        assert_eq!(ctx.app_name, "demo");
        assert_eq!(ctx.repo_url, "https://example.com/repo.git");
        assert_eq!(ctx.source_path, "apps/prod");
        assert_eq!(ctx.destination_namespace, "payments");
        assert_eq!(ctx.cluster_kube_version, "1.35.0");
        assert!(
            ctx.commit_sha.is_empty(),
            "the caller attaches the resolved commit with with_commit_sha"
        );

        match &ctx.renderer {
            RendererConfig::Helm(options) => {
                assert_eq!(options.release_name.as_deref(), Some("prod"));
                assert_eq!(options.value_files, vec!["values-prod.yaml".to_owned()]);
                assert!(options.include_crds);
            }
            other => panic!("expected a helm renderer, got {other:?}"),
        }
    }

    #[test]
    fn render_context_debug_redacts_credentials_and_inline_values() {
        let ctx = RenderContext::new("/repo")
            .with_repo_url("https://robot:s3cr3t-token@example.com/monorepo.git")
            .with_app("ferriscd-system", "demo")
            .with_renderer(RendererConfig::Helm(HelmOptions {
                inline_values: Some("password: hunter2\n".to_owned()),
                set: vec!["db.password=hunter2".to_owned()],
                set_string: vec!["api.key=hunter2".to_owned()],
                ..HelmOptions::default()
            }));

        let rendered = format!("{ctx:?}");
        assert!(!rendered.contains("s3cr3t-token"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("robot:***@example.com"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");

        // Finding C1: a *bare* userinfo is a token, not a username, so nothing of it survives.
        let bare = RenderContext::new("/repo")
            .with_repo_url("https://ghp_16C7e42Ftoken@github.com/org/repo.git")
            .with_app("ferriscd-system", "demo");
        let rendered = format!("{bare:?}");
        assert!(!rendered.contains("ghp_16C7e42Ftoken"), "{rendered}");
        assert!(
            rendered.contains("https://***@github.com/org/repo.git"),
            "{rendered}"
        );
    }

    #[test]
    fn repo_url_redaction_covers_every_userinfo_shape() {
        // (input, expected)
        let cases = [
            // Credentialed URLs: the username survives, the secret never does.
            (
                "https://robot:s3cr3t-token@example.com/monorepo.git",
                "https://robot:***@example.com/monorepo.git",
            ),
            (
                "https://oauth2:abc123@gitlab.com/g/r.git",
                "https://oauth2:***@gitlab.com/g/r.git",
            ),
            // A bare userinfo is a token: it must be redacted whole (finding C1).
            (
                "https://ghp_16C7e42Ftoken@github.com/org/repo.git",
                "https://***@github.com/org/repo.git",
            ),
            // No colon → no username to keep, even for SSH-style URLs.
            ("ssh://user@host/repo.git", "ssh://***@host/repo.git"),
            // A missing username still must not print the token.
            ("https://:tok3n@host/repo.git", "https://***@host/repo.git"),
            // Nothing to redact: passed through untouched.
            (
                "https://example.com/repo.git",
                "https://example.com/repo.git",
            ),
            ("git@github.com:org/repo.git", "git@github.com:org/repo.git"),
            (
                "https://example.com/team@corp/repo.git",
                "https://example.com/team@corp/repo.git",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(redact_repo_url(input), expected, "input '{input}'");
        }
    }

    #[test]
    fn renderer_config_canonical_form_is_unambiguous() {
        let prefix_a = RendererConfig::Kustomize(KustomizeOptions {
            name_prefix: Some("a".to_owned()),
            name_suffix: Some("b".to_owned()),
            ..KustomizeOptions::default()
        });
        let prefix_b = RendererConfig::Kustomize(KustomizeOptions {
            name_prefix: Some("ab".to_owned()),
            ..KustomizeOptions::default()
        });
        assert_ne!(prefix_a.canonical(), prefix_b.canonical());

        // A value containing the encoder's own separators cannot collide with two fields.
        let sneaky = RendererConfig::Kustomize(KustomizeOptions {
            name_prefix: Some("a;1:b".to_owned()),
            ..KustomizeOptions::default()
        });
        assert_ne!(sneaky.canonical(), prefix_a.canonical());

        assert_eq!(
            RendererConfig::Auto.canonical(),
            RendererConfig::Auto.canonical()
        );
        assert_ne!(
            RendererConfig::PlainYaml(PlainYamlOptions { recursive: true }).canonical(),
            RendererConfig::PlainYaml(PlainYamlOptions { recursive: false }).canonical()
        );
    }

    #[test]
    fn remote_reference_detection_covers_urls_and_vcs_shorthands() {
        for reference in [
            "https://example.com/base",
            "http://169.254.169.254/latest/meta-data/",
            "ssh://git@example.com/repo",
            "git::https://example.com/repo.git//base?ref=v1",
            "git@github.com:org/repo.git",
            "github.com/org/repo//base",
            "//example.com/base",
            "/etc/passwd",
            "https://example.com/base?ref=main",
        ] {
            assert!(
                is_remote_reference(reference),
                "'{reference}' must be treated as remote/absolute"
            );
        }

        for reference in [
            "base",
            "../base",
            "../../base",
            "deployment.yaml",
            "patches/prod.yaml",
            "./base",
            "",
        ] {
            assert!(
                !is_remote_reference(reference),
                "'{reference}' is a local reference"
            );
        }
    }

    #[test]
    fn crd_renderer_specs_map_onto_engine_configuration() {
        assert_eq!(
            RendererConfig::from_crd(&RendererSpec::default()),
            RendererConfig::Auto
        );

        let plain = ferriscd_crd::PlainYamlRenderer { recursive: false };
        assert_eq!(
            RendererConfig::from_crd(&RendererSpec::PlainYaml(plain)),
            RendererConfig::PlainYaml(PlainYamlOptions { recursive: false })
        );

        let kustomize = ferriscd_crd::KustomizeRenderer {
            kustomization_path: Some("overlays/prod".to_owned()),
            images: vec!["nginx=registry.example.com/nginx:1.28-alpine".to_owned()],
        };
        match RendererConfig::from_crd(&RendererSpec::Kustomize(kustomize)) {
            RendererConfig::Kustomize(options) => {
                assert_eq!(options.kustomization_path.as_deref(), Some("overlays/prod"));
                assert_eq!(options.images.len(), 1);
                // Engine-only knobs stay at their defaults until the CRD exposes them.
                assert!(options.name_prefix.is_none());
            }
            other => panic!("expected kustomize, got {other:?}"),
        }

        let helm = ferriscd_crd::HelmRenderer {
            release_name: Some("prod".to_owned()),
            value_files: vec!["values-prod.yaml".to_owned()],
            include_crds: false,
        };
        match RendererConfig::from_crd(&RendererSpec::Helm(helm)) {
            RendererConfig::Helm(options) => {
                assert_eq!(options.release_name.as_deref(), Some("prod"));
                assert_eq!(options.value_files, vec!["values-prod.yaml".to_owned()]);
                assert!(!options.include_crds, "CRDs stay opt-in");
            }
            other => panic!("expected helm, got {other:?}"),
        }
    }
}
