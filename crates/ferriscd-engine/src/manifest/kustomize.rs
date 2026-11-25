//! Kustomize v5 renderer with a remote-base SSRF guard and a path jail.
//!
//! # Why the guard exists
//!
//! `kustomize build --load-restrictor=LoadRestrictionsRootOnly` stops a *local* file from being
//! loaded outside the kustomization root. It does **not** stop `resources: [https://...]`,
//! `bases: [git::...]`, or `components: [github.com/org/repo//x]`: those are fetched over the
//! network by kustomize itself. A malicious repository could therefore use the renderer as an
//! SSRF proxy (cloud metadata, in-cluster services, or a private Git host that `AppProject`
//! credentials never authorized). See Finding C7.
//!
//! [`guard_kustomization_tree`] therefore reads the kustomization graph **before** any subprocess
//! runs and rejects:
//!
//! * any remote URL or VCS shorthand in `resources`, `bases`, `components`, `patches`,
//!   `patchesStrategicMerge`, `patchesJson6902`, `configurations`, `crds`, `generators`,
//!   `transformers` — including inside referenced local sub-kustomizations,
//! * any reference that canonicalizes outside the immutable checkout (`../../escape`),
//! * `helmCharts` (it requires the `--enable-helm` plugin, which is never enabled),
//! * glob references (their expansion cannot be checked before kustomize runs).
//!
//! # Two-phase build (prefix/suffix/image overrides without mutating the checkout)
//!
//! `LoadRestrictionsRootOnly` also refuses a resource *outside* the kustomization directory, so an
//! overlay cannot simply point at the cached worktree from a scratch directory. Instead:
//!
//! 1. `kustomize build <checkout path> --load-restrictor=LoadRestrictionsRootOnly` — the repository
//!    is rendered read-only and never modified,
//! 2. when `namePrefix`/`nameSuffix`/`images` are configured, the phase-1 output is written to a
//!    scratch directory and a second `kustomize build` applies the transforms to that bundle.
//!
//! Both phases run through [`SandboxedCommand`] (cleared env, dead proxy, hard deadline, bounded
//! output), and plugin flags (`--enable-exec`, `--enable-alpha-plugins`, `--enable-helm`) are never
//! passed.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ferriscd_crd::KustomizeRenderer as CrdKustomizeRenderer;
use serde_json::{Map, Value, json};

use super::error::ManifestError;
use super::exec::{ExecError, SandboxedCommand};
use super::loader::ManifestFile;
use super::renderer::{
    ManifestRenderer, RenderContext, RenderFuture, RendererKind, canonical_root, contained_file,
    is_remote_reference, relative_display, resolve_relative_inside, resolve_source_path,
    task_failed,
};
use super::yaml::parse_options;

/// Renderer name used in errors and logs.
const RENDERER: &str = "kustomize";

/// Kustomization file names understood by kustomize v5 (checked in this order).
const KUSTOMIZATION_FILES: [&str; 3] = ["kustomization.yaml", "kustomization.yml", "Kustomization"];

/// Maximum accepted size of one parsed kustomization file.
const MAX_KUSTOMIZATION_BYTES: u64 = 1024 * 1024;

/// Maximum number of kustomizations traversed by the guard (cycle/bomb bound).
const MAX_KUSTOMIZATIONS: usize = 256;

/// Maximum reference depth traversed by the guard.
const MAX_REFERENCE_DEPTH: usize = 16;

/// The only load restrictor FerrisCD ever passes.
const LOAD_RESTRICTOR_ARG: &str = "--load-restrictor=LoadRestrictionsRootOnly";

/// List-valued fields whose entries are *paths or URLs* to other kustomizations or files.
const PATH_LIST_FIELDS: [&str; 8] = [
    "resources",
    "bases",
    "components",
    "configurations",
    "crds",
    "generators",
    "transformers",
    "patchesStrategicMerge",
];

/// Fields whose entries are either a path (`- path.yaml`) or an object with a `path` key.
const PATCH_FIELDS: [&str; 2] = ["patches", "patchesJson6902"];

/// Generators whose `files`/`envs` entries are file-system paths too.
const GENERATOR_FIELDS: [&str; 2] = ["configMapGenerator", "secretGenerator"];

/// Keys inside a generator entry that hold paths (`files` entries may be `key=path`).
const GENERATOR_PATH_KEYS: [&str; 3] = ["files", "envs", "env"];

/// Kustomize renderer configuration.
///
/// The `binary`, `timeout`, and `max_output_bytes` fields are engine/operator knobs (tests point
/// `binary` at a fake script); they are deliberately excluded from the render cache key because
/// they cannot change *what* a given commit renders to for a given kustomize version.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct KustomizeOptions {
    /// Overlay directory relative to `spec.source.git.path`; defaults to the source path.
    pub kustomization_path: Option<String>,
    /// `namePrefix` transform applied by a scratch overlay after the build.
    pub name_prefix: Option<String>,
    /// `nameSuffix` transform applied by a scratch overlay after the build.
    pub name_suffix: Option<String>,
    /// Image overrides (`name=newName:tag`) applied by a scratch overlay after the build.
    pub images: Vec<String>,
    /// Overrides the `kustomize` binary: an absolute path or a bare `PATH` name (relative paths
    /// are rejected by the sandbox).
    pub binary: Option<PathBuf>,
    /// Overrides the hard execution deadline.
    pub timeout: Option<Duration>,
    /// Overrides the bounded output cap.
    pub max_output_bytes: Option<u64>,
}

impl KustomizeOptions {
    /// Maps the CRD's `spec.source.renderer.kustomize` onto engine options.
    #[must_use]
    pub fn from_crd(spec: &CrdKustomizeRenderer) -> Self {
        Self {
            kustomization_path: spec.kustomization_path.clone(),
            images: spec.images.clone(),
            ..Self::default()
        }
    }

    /// Returns `true` when the scratch post-build overlay is required.
    fn needs_overlay(&self) -> bool {
        self.name_prefix
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            || self
                .name_suffix
                .as_deref()
                .is_some_and(|value| !value.is_empty())
            || !self.images.is_empty()
    }
}

/// `kustomize build` renderer.
#[derive(Clone, Debug, Default)]
pub struct KustomizeRenderer {
    options: KustomizeOptions,
}

impl KustomizeRenderer {
    /// Creates a renderer with the given options.
    #[must_use]
    pub fn new(options: KustomizeOptions) -> Self {
        Self { options }
    }

    /// Runs `kustomize build <dir>` through the sandbox and returns stdout.
    async fn build(&self, dir: &Path) -> Result<String, ManifestError> {
        let program = self
            .options
            .binary
            .clone()
            .unwrap_or_else(|| PathBuf::from(RENDERER));
        let mut command = SandboxedCommand::new(program.into_os_string())
            .arg("build")
            .arg(dir.as_os_str())
            .arg(LOAD_RESTRICTOR_ARG)
            .current_dir(dir);
        if let Some(timeout) = self.options.timeout {
            command = command.timeout(timeout);
        }
        if let Some(max_bytes) = self.options.max_output_bytes {
            command = command.max_output_bytes(max_bytes);
        }

        let output = command.run().await.map_err(map_exec_error)?;
        Ok(output.stdout)
    }
}

impl ManifestRenderer for KustomizeRenderer {
    fn kind(&self) -> RendererKind {
        RendererKind::Kustomize
    }

    fn render<'a>(&'a self, ctx: &'a RenderContext) -> RenderFuture<'a, Vec<ManifestFile>> {
        Box::pin(async move {
            let root = ctx.root_dir.clone();
            let source_path = ctx.source_path.clone();
            let options = self.options.clone();

            // Path resolution, the remote/escape guard, and scratch setup are blocking work.
            let prepared =
                tokio::task::spawn_blocking(move || prepare(&root, &source_path, &options))
                    .await
                    .map_err(|join_err| task_failed(RendererKind::Kustomize, join_err))??;

            let source_file = format!("kustomize:{}", prepared.relative_target);
            let first = self.build(&prepared.target_dir).await?;

            if !self.options.needs_overlay() {
                return Ok(vec![ManifestFile {
                    source_file,
                    contents: first,
                }]);
            }

            let overlay_dir = prepared.scratch.path().join("overlay");
            let options = self.options.clone();
            let overlay =
                tokio::task::spawn_blocking(move || write_overlay(&overlay_dir, &first, &options))
                    .await
                    .map_err(|join_err| task_failed(RendererKind::Kustomize, join_err))??;

            let second = self.build(&overlay).await?;
            Ok(vec![ManifestFile {
                source_file,
                contents: second,
            }])
        })
    }
}

/// Blocking preparation: resolve the kustomization directory, guard it, and create scratch space.
#[derive(Debug)]
struct PreparedKustomize {
    target_dir: PathBuf,
    relative_target: String,
    scratch: tempfile::TempDir,
}

fn prepare(
    root: &Path,
    source_path: &str,
    options: &KustomizeOptions,
) -> Result<PreparedKustomize, ManifestError> {
    let canonical = canonical_root(root)?;
    let source_dir = resolve_source_path(&canonical, source_path)?;
    if !source_dir.is_dir() {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "kustomize requires a directory, but '{}' is not one",
                source_dir.display()
            ),
        });
    }

    let target_dir = match options.kustomization_path.as_deref() {
        Some(path) if !path.trim().is_empty() => {
            resolve_relative_inside(&canonical, &source_dir, path)?
        }
        _ => source_dir,
    };
    if !target_dir.is_dir() {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "kustomization path '{}' is not a directory",
                target_dir.display()
            ),
        });
    }
    if kustomization_file(&canonical, &target_dir)?.is_none() {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "no kustomization.yaml/kustomization.yml/Kustomization in '{}'",
                relative_display(&canonical, &target_dir)
            ),
        });
    }

    guard_kustomization_tree(&canonical, &target_dir)?;

    let scratch = tempfile::Builder::new()
        .prefix("ferriscd-kustomize-")
        .tempdir()
        .map_err(|source| ManifestError::Io {
            context: "creating the kustomize scratch directory".to_owned(),
            source,
        })?;

    let relative_target = relative_display(&canonical, &target_dir);
    Ok(PreparedKustomize {
        target_dir,
        relative_target,
        scratch,
    })
}

/// Walks the kustomization graph reachable from `target_dir`, rejecting unsafe references.
///
/// Every reference is checked *before* any subprocess runs, so a malicious `resources:` entry can
/// never reach kustomize's downloader.
fn guard_kustomization_tree(root: &Path, target_dir: &Path) -> Result<(), ManifestError> {
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((target_dir.to_path_buf(), 0));

    while let Some((dir, depth)) = queue.pop_front() {
        if depth > MAX_REFERENCE_DEPTH {
            return Err(ManifestError::RendererRejected {
                renderer: RENDERER.to_owned(),
                message: format!(
                    "kustomization reference depth exceeded {MAX_REFERENCE_DEPTH} at '{}'",
                    relative_display(root, &dir)
                ),
            });
        }
        if !visited.insert(dir.clone()) {
            continue;
        }
        if visited.len() > MAX_KUSTOMIZATIONS {
            return Err(ManifestError::RendererRejected {
                renderer: RENDERER.to_owned(),
                message: format!(
                    "more than {MAX_KUSTOMIZATIONS} kustomizations are reachable from '{}'",
                    relative_display(root, target_dir)
                ),
            });
        }

        let Some(file) = kustomization_file(root, &dir)? else {
            continue;
        };
        let relative_file = relative_display(root, &file);
        let document = read_kustomization(root, &file)?;
        let references = collect_references(&relative_file, &document)?;

        for reference in references {
            let resolved = check_reference(root, &relative_file, &dir, &reference)?;
            if let Some(next_dir) = resolved {
                queue.push_back((next_dir, depth + 1));
            }
        }
    }

    Ok(())
}

/// One reference extracted from a kustomization document.
struct Reference {
    field: &'static str,
    value: String,
}

/// Extracts every path/URL-valued reference, rejecting malformed and plugin-only fields.
fn collect_references(
    relative_file: &str,
    document: &Value,
) -> Result<Vec<Reference>, ManifestError> {
    let Some(object) = document.as_object() else {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!("'{relative_file}' must be a mapping"),
        });
    };

    if object.contains_key("helmCharts") {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "'{relative_file}' uses helmCharts, which needs the disabled --enable-helm plugin"
            ),
        });
    }

    let mut references = Vec::new();

    for generator in GENERATOR_FIELDS {
        let Some(items) = object.get(generator) else {
            continue;
        };
        let Some(items) = items.as_array() else {
            return Err(ManifestError::RendererRejected {
                renderer: RENDERER.to_owned(),
                message: format!("'{relative_file}': {generator} must be a list"),
            });
        };
        for item in items {
            let Some(entry) = item.as_object() else {
                continue;
            };
            for key in GENERATOR_PATH_KEYS {
                let Some(paths) = entry.get(key).and_then(Value::as_array) else {
                    continue;
                };
                for path in paths {
                    let Some(path) = path.as_str() else { continue };
                    // `files: [key=path]` carries the destination key before the path.
                    let path = path.split_once('=').map_or(path, |(_, path)| path);
                    references.push(Reference {
                        field: generator,
                        value: path.to_owned(),
                    });
                }
            }
        }
    }

    for field in PATH_LIST_FIELDS {
        let Some(value) = object.get(field) else {
            continue;
        };
        let Some(items) = value.as_array() else {
            return Err(ManifestError::RendererRejected {
                renderer: RENDERER.to_owned(),
                message: format!("'{relative_file}': {field} must be a list"),
            });
        };
        for item in items {
            let text = item
                .as_str()
                .ok_or_else(|| ManifestError::RendererRejected {
                    renderer: RENDERER.to_owned(),
                    message: format!("'{relative_file}': every {field} entry must be a string"),
                })?;
            references.push(Reference {
                field,
                value: text.to_owned(),
            });
        }
    }

    for field in PATCH_FIELDS {
        let Some(value) = object.get(field) else {
            continue;
        };
        let Some(items) = value.as_array() else {
            return Err(ManifestError::RendererRejected {
                renderer: RENDERER.to_owned(),
                message: format!("'{relative_file}': {field} must be a list"),
            });
        };
        for item in items {
            let path = match item {
                // Inline patches (`patch: |`) carry no path and need no guard.
                Value::Object(entry) => entry.get("path").and_then(Value::as_str),
                Value::String(text) => Some(text.as_str()),
                _ => None,
            };
            if let Some(path) = path {
                references.push(Reference {
                    field,
                    value: path.to_owned(),
                });
            }
        }
    }

    Ok(references)
}

/// Validates one reference; returns the directory to recurse into when it is a kustomization.
fn check_reference(
    root: &Path,
    relative_file: &str,
    kustomization_dir: &Path,
    reference: &Reference,
) -> Result<Option<PathBuf>, ManifestError> {
    let value = reference.value.trim();
    if is_remote_reference(value) {
        return Err(ManifestError::UnsafeReference {
            file: relative_file.to_owned(),
            field: reference.field.to_owned(),
            reference: reference.value.clone(),
            reason: "remote URLs, VCS shorthands, and absolute paths are blocked for kustomize \
                     references"
                .to_owned(),
        });
    }
    if value.contains('*') || value.contains('?') {
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "'{relative_file}': glob reference '{}' cannot be validated before the build",
                reference.value
            ),
        });
    }

    let resolved = resolve_relative_inside(root, kustomization_dir, value).map_err(|err| {
        // A reference that resolves outside the checkout is an escape attempt, not a typo.
        match err {
            ManifestError::PathEscape { path, .. } => ManifestError::UnsafeReference {
                file: relative_file.to_owned(),
                field: reference.field.to_owned(),
                reference: reference.value.clone(),
                reason: format!("resolves outside the checkout root ('{path}')"),
            },
            other => other,
        }
    })?;

    if resolved.is_dir() {
        if kustomization_file(root, &resolved)?.is_some() {
            return Ok(Some(resolved));
        }
        return Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!(
                "'{relative_file}': '{}' is a directory without a kustomization file",
                reference.value
            ),
        });
    }

    Ok(None)
}

/// Returns the kustomization file inside `dir`, if one exists and stays inside the checkout.
fn kustomization_file(root: &Path, dir: &Path) -> Result<Option<PathBuf>, ManifestError> {
    for name in KUSTOMIZATION_FILES {
        if let Some(file) = contained_file(root, &dir.join(name))? {
            return Ok(Some(file));
        }
    }
    Ok(None)
}

/// Reads and parses one kustomization file under the Phase 03 YAML options and a size cap.
fn read_kustomization(root: &Path, file: &Path) -> Result<Value, ManifestError> {
    let relative = relative_display(root, file);
    let metadata = std::fs::metadata(file).map_err(|source| ManifestError::Io {
        context: format!("inspecting kustomization '{relative}'"),
        source,
    })?;
    if metadata.len() > MAX_KUSTOMIZATION_BYTES {
        return Err(ManifestError::LimitExceeded {
            reason: format!(
                "kustomization '{relative}' is {} bytes, above the {MAX_KUSTOMIZATION_BYTES}-byte \
                 limit",
                metadata.len()
            ),
        });
    }

    let contents = std::fs::read_to_string(file).map_err(|source| ManifestError::Io {
        context: format!("reading kustomization '{relative}'"),
        source,
    })?;

    let parsed: Option<Value> = serde_saphyr::from_str_with_options(&contents, parse_options())
        .map_err(|err| ManifestError::YamlParse {
            file: relative.clone(),
            doc: 1,
            message: err.to_string(),
        })?;

    match parsed {
        Some(value) if !value.is_null() => Ok(value),
        _ => Err(ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!("'{relative}' is empty"),
        }),
    }
}

/// Writes the phase-2 overlay that applies prefix/suffix/image transforms to the rendered bundle.
///
/// Both files are written as JSON, which is a strict subset of YAML 1.2, so no user-controlled
/// string can inject YAML structure into the generated kustomization.
fn write_overlay(
    overlay_dir: &Path,
    rendered: &str,
    options: &KustomizeOptions,
) -> Result<PathBuf, ManifestError> {
    std::fs::create_dir_all(overlay_dir).map_err(|source| ManifestError::Io {
        context: format!("creating overlay directory '{}'", overlay_dir.display()),
        source,
    })?;
    std::fs::write(overlay_dir.join("rendered.yaml"), rendered).map_err(|source| {
        ManifestError::Io {
            context: "writing the rendered bundle into scratch space".to_owned(),
            source,
        }
    })?;

    let mut document = Map::new();
    document.insert(
        "apiVersion".to_owned(),
        Value::String("kustomize.config.k8s.io/v1beta1".to_owned()),
    );
    document.insert("kind".to_owned(), Value::String("Kustomization".to_owned()));
    document.insert("resources".to_owned(), json!(["rendered.yaml"]));
    if let Some(prefix) = options
        .name_prefix
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        document.insert("namePrefix".to_owned(), Value::String(prefix.to_owned()));
    }
    if let Some(suffix) = options
        .name_suffix
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        document.insert("nameSuffix".to_owned(), Value::String(suffix.to_owned()));
    }
    if !options.images.is_empty() {
        let images = options
            .images
            .iter()
            .map(|entry| parse_image_override(entry))
            .collect::<Result<Vec<Value>, ManifestError>>()?;
        document.insert("images".to_owned(), Value::Array(images));
    }

    let serialized = serde_json::to_string(&Value::Object(document)).map_err(|err| {
        ManifestError::RendererRejected {
            renderer: RENDERER.to_owned(),
            message: format!("failed to serialize the scratch overlay: {err}"),
        }
    })?;
    std::fs::write(overlay_dir.join("kustomization.yaml"), serialized).map_err(|source| {
        ManifestError::Io {
            context: "writing the scratch overlay kustomization".to_owned(),
            source,
        }
    })?;

    Ok(overlay_dir.to_path_buf())
}

/// Converts one `name=newName:tag` override into kustomize v5's structured image entry.
///
/// v5 rejects the bare string form (`images: [nginx=...]`), so the string is split into
/// `name`/`newName`/`newTag`/`digest` here rather than being passed through.
fn parse_image_override(entry: &str) -> Result<Value, ManifestError> {
    let reject = |message: String| ManifestError::RendererRejected {
        renderer: RENDERER.to_owned(),
        message,
    };

    let Some((name, replacement)) = entry.split_once('=') else {
        return Err(reject(format!(
            "image override '{entry}' must have the form name=newName[:tag]"
        )));
    };
    let name = name.trim();
    let replacement = replacement.trim();
    if name.is_empty() || replacement.is_empty() {
        return Err(reject(format!(
            "image override '{entry}' must have a non-empty name and replacement"
        )));
    }

    let (image_ref, digest) = match replacement.split_once('@') {
        Some((image_ref, digest)) => (image_ref, Some(digest)),
        None => (replacement, None),
    };

    // A tag can only follow the last path segment: `registry:5000/nginx` has no tag.
    let last_segment = image_ref.rfind('/').map_or(0, |index| index + 1);
    let (repository, tag) = match image_ref[last_segment..].rfind(':') {
        Some(offset) => {
            let split = last_segment + offset;
            (&image_ref[..split], Some(&image_ref[split + 1..]))
        }
        None => (image_ref, None),
    };
    if repository.is_empty() {
        return Err(reject(format!(
            "image override '{entry}' has an empty repository"
        )));
    }

    let mut image = Map::new();
    image.insert("name".to_owned(), Value::String(name.to_owned()));
    image.insert("newName".to_owned(), Value::String(repository.to_owned()));
    if let Some(tag) = tag.filter(|tag| !tag.is_empty()) {
        image.insert("newTag".to_owned(), Value::String(tag.to_owned()));
    }
    if let Some(digest) = digest.filter(|digest| !digest.is_empty()) {
        image.insert("digest".to_owned(), Value::String(digest.to_owned()));
    }
    Ok(Value::Object(image))
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

    /// Renders `overlays/prod` with the given renderer options.
    fn context(root: &Path, options: KustomizeOptions) -> RenderContext {
        RenderContext::new(root)
            .with_source_path("overlays/prod")
            .with_renderer(RendererConfig::Kustomize(options))
    }

    /// Minimal base + overlay fixture (`overlays/prod` -> `../../base`).
    fn fixture(root: &Path) {
        write(
            root,
            "base/kustomization.yaml",
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - deployment.yaml\n",
        );
        write(
            root,
            "base/deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n",
        );
        write(
            root,
            "overlays/prod/kustomization.yaml",
            "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n  - ../../base\n",
        );
    }

    fn fake_kustomize(root: &Path) -> FakeBinary {
        let fake = FakeBinary::new(
            "kustomize",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: web\n",
        );
        // Keep the fake alive next to the fixture root for the duration of the test.
        let _ = root;
        fake
    }

    async fn render_error(root: &Path, options: KustomizeOptions) -> ManifestError {
        KustomizeRenderer::new(options.clone())
            .render(&context(root, options))
            .await
            .expect_err("render must fail")
    }

    #[tokio::test]
    async fn remote_resource_url_is_rejected_before_kustomize_runs() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        write(
            root,
            "overlays/prod/kustomization.yaml",
            "resources:\n  - http://169.254.169.254/latest/meta-data/\n",
        );

        let fake = FakeBinary::new(
            "kustomize",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        );
        let options = KustomizeOptions {
            binary: Some(fake.path().to_path_buf()),
            ..KustomizeOptions::default()
        };
        let err = render_error(root, options).await;

        match &err {
            ManifestError::UnsafeReference {
                reference, field, ..
            } => {
                assert_eq!(field, "resources");
                assert_eq!(reference, "http://169.254.169.254/latest/meta-data/");
            }
            other => panic!("expected UnsafeReference, got {other:?}"),
        }
        assert_eq!(
            fake.invocations(),
            0,
            "kustomize must never be spawned for a rejected reference"
        );
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn escaping_parent_reference_is_rejected_before_kustomize_runs() {
        let base = TempDir::new().expect("tempdir");
        let root = base.path().join("repo");
        fs::create_dir_all(&root).expect("create repo root");
        fixture(&root);
        write(base.path(), "outside/kustomization.yaml", "resources: []\n");
        write(
            &root,
            "overlays/prod/kustomization.yaml",
            "resources:\n  - ../../../outside\n",
        );

        let fake = FakeBinary::new(
            "kustomize",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        );
        let options = KustomizeOptions {
            binary: Some(fake.path().to_path_buf()),
            ..KustomizeOptions::default()
        };
        let err = render_error(&root, options).await;

        match &err {
            ManifestError::UnsafeReference {
                reference, reason, ..
            } => {
                assert_eq!(reference, "../../../outside");
                assert!(reason.contains("outside the checkout"), "{reason}");
            }
            other => panic!("expected UnsafeReference, got {other:?}"),
        }
        assert_eq!(fake.invocations(), 0);
    }

    #[tokio::test]
    async fn remote_references_in_a_nested_sub_kustomization_are_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        // The overlay's base looks local, but the base itself pulls a remote component.
        write(
            root,
            "base/kustomization.yaml",
            "resources:\n  - deployment.yaml\ncomponents:\n  - git::https://example.com/repo.git//x?ref=v1\n",
        );

        let fake = FakeBinary::new(
            "kustomize",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        );
        let options = KustomizeOptions {
            binary: Some(fake.path().to_path_buf()),
            ..KustomizeOptions::default()
        };
        let err = render_error(root, options).await;

        match &err {
            ManifestError::UnsafeReference { file, field, .. } => {
                assert_eq!(file, "base/kustomization.yaml");
                assert_eq!(field, "components");
            }
            other => panic!("expected UnsafeReference, got {other:?}"),
        }
        assert_eq!(fake.invocations(), 0);
    }

    #[tokio::test]
    async fn helm_charts_are_rejected_because_the_plugin_is_disabled() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        write(
            root,
            "overlays/prod/kustomization.yaml",
            "helmCharts:\n  - name: demo\n    repo: https://example.com/charts\n",
        );

        let options = KustomizeOptions {
            binary: Some(temp.path().join("kustomize-not-installed")),
            ..KustomizeOptions::default()
        };
        let err = render_error(root, options).await;
        assert!(
            err.to_string().contains("--enable-helm"),
            "the error must name the disabled plugin: {err}"
        );
    }

    #[tokio::test]
    async fn generator_file_paths_are_guarded_too() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        write(
            root,
            "overlays/prod/kustomization.yaml",
            "resources:\n  - ../../base\nconfigMapGenerator:\n  - name: env\n    files:\n      - key=../../../etc/passwd\n",
        );

        let fake = FakeBinary::new(
            "kustomize",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        );
        let options = KustomizeOptions {
            binary: Some(fake.path().to_path_buf()),
            ..KustomizeOptions::default()
        };
        let err = render_error(root, options).await;

        match &err {
            ManifestError::UnsafeReference {
                field, reference, ..
            } => {
                assert_eq!(field, "configMapGenerator");
                assert_eq!(reference, "../../../etc/passwd");
            }
            other => panic!("expected UnsafeReference, got {other:?}"),
        }
        assert_eq!(fake.invocations(), 0);
    }

    #[tokio::test]
    async fn glob_references_are_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        write(
            root,
            "overlays/prod/kustomization.yaml",
            "resources:\n  - patches/*.yaml\n",
        );

        let options = KustomizeOptions {
            binary: Some(temp.path().join("kustomize-not-installed")),
            ..KustomizeOptions::default()
        };
        let err = render_error(root, options).await;
        assert!(err.to_string().contains("glob"), "{err}");
    }

    #[tokio::test]
    async fn build_args_are_pinned_and_never_enable_plugins() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let fake = fake_kustomize(root);
        let options = KustomizeOptions {
            binary: Some(fake.path().to_path_buf()),
            ..KustomizeOptions::default()
        };

        let files = KustomizeRenderer::new(options.clone())
            .render(&context(root, options))
            .await
            .expect("render");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].source_file, "kustomize:overlays/prod");
        assert_eq!(fake.invocations(), 1);

        let args = fake.recorded_args();
        assert_eq!(args[0], "build");
        assert!(
            args.iter().any(|arg| arg == LOAD_RESTRICTOR_ARG),
            "the load restrictor must always be passed: {args:?}"
        );
        assert!(
            args.iter().any(|arg| arg.ends_with("overlays/prod")),
            "the checkout target must be passed: {args:?}"
        );
        for forbidden in [
            "--enable-exec",
            "--enable-alpha-plugins",
            "--enable-helm",
            "--load-restrictor=LoadRestrictionsNone",
        ] {
            assert!(
                !args.iter().any(|arg| arg == forbidden),
                "{forbidden} must never be passed: {args:?}"
            );
        }
    }

    #[tokio::test]
    async fn prefix_suffix_and_images_are_applied_by_a_scratch_overlay() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let rendered = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n";
        let fake = FakeBinary::new("kustomize", rendered);
        let options = KustomizeOptions {
            binary: Some(fake.path().to_path_buf()),
            name_prefix: Some("prod-".to_owned()),
            name_suffix: Some("-v2".to_owned()),
            images: vec!["nginx=registry.example.com/nginx:1.28-alpine".to_owned()],
            ..KustomizeOptions::default()
        };

        let files = KustomizeRenderer::new(options.clone())
            .render(&context(root, options))
            .await
            .expect("render with overlay");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].contents.trim_end(), rendered.trim_end());
        assert_eq!(
            fake.invocations(),
            2,
            "a post-build overlay must be a second kustomize invocation"
        );

        let args = fake.recorded_args();
        let overlay_path = args
            .iter()
            .find(|arg| arg.ends_with("/overlay"))
            .unwrap_or_else(|| panic!("the scratch overlay must be built: {args:?}"));
        assert!(
            overlay_path.contains("ferriscd-kustomize-"),
            "the overlay must live in scratch space: {overlay_path}"
        );
        assert!(
            !Path::new(overlay_path)
                .starts_with(std::fs::canonicalize(root).expect("canonical checkout root")),
            "the cached worktree must never be mutated"
        );

        let overlays = fake.recorded_kustomizations();
        assert_eq!(overlays.len(), 2, "{overlays:?}");
        // The first recorded file is the repository's own (unmodified) kustomization...
        assert!(overlays[0].contains("../../base"), "{}", overlays[0]);
        // ...and the second is the generated, transform-only overlay.
        let generated = &overlays[1];
        assert!(
            generated.contains("\"namePrefix\":\"prod-\""),
            "{generated}"
        );
        assert!(generated.contains("\"nameSuffix\":\"-v2\""), "{generated}");
        assert!(generated.contains("\"name\":\"nginx\""), "{generated}");
        assert!(
            generated.contains("\"newName\":\"registry.example.com/nginx\""),
            "{generated}"
        );
        assert!(
            generated.contains("\"newTag\":\"1.28-alpine\""),
            "{generated}"
        );
    }

    #[test]
    fn image_overrides_parse_tags_registry_ports_and_digests() {
        let tag = parse_image_override("nginx=registry.example.com/nginx:1.28-alpine")
            .expect("tag override");
        assert_eq!(tag["name"], json!("nginx"));
        assert_eq!(tag["newName"], json!("registry.example.com/nginx"));
        assert_eq!(tag["newTag"], json!("1.28-alpine"));

        let port = parse_image_override("nginx=registry:5000/nginx").expect("registry port");
        assert_eq!(port["newName"], json!("registry:5000/nginx"));
        assert!(port.get("newTag").is_none(), "{port}");

        let digest =
            parse_image_override("nginx=registry.example.com/nginx@sha256:abc").expect("digest");
        assert_eq!(digest["newName"], json!("registry.example.com/nginx"));
        assert_eq!(digest["digest"], json!("sha256:abc"));

        for invalid in ["nginx", "=nginx:1", "nginx=", ""] {
            assert!(
                parse_image_override(invalid).is_err(),
                "'{invalid}' must be rejected"
            );
        }
    }

    #[test]
    fn kustomization_path_option_must_stay_inside_the_checkout() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        write(
            root,
            "overlays/prod/patches/kustomization.yaml",
            "resources: []\n",
        );

        let prepared = prepare(
            root,
            "overlays/prod",
            &KustomizeOptions {
                kustomization_path: Some("patches".to_owned()),
                ..KustomizeOptions::default()
            },
        )
        .expect("prepare");
        assert_eq!(prepared.relative_target, "overlays/prod/patches");

        let err = prepare(
            root,
            "overlays/prod",
            &KustomizeOptions {
                kustomization_path: Some("../../..".to_owned()),
                ..KustomizeOptions::default()
            },
        )
        .expect_err("escaping overlay path must fail");
        assert!(matches!(err, ManifestError::PathEscape { .. }), "{err:?}");
    }

    #[test]
    fn directory_without_a_kustomization_file_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        write(
            root,
            "plain/configmap.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n",
        );

        let err = prepare(root, "plain", &KustomizeOptions::default())
            .expect_err("missing kustomization must fail");
        assert!(
            err.to_string().contains("no kustomization"),
            "the error must explain what is missing: {err}"
        );
    }

    #[tokio::test]
    async fn missing_binary_surfaces_as_a_renderer_failure() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();
        fixture(root);
        let options = KustomizeOptions {
            binary: Some(root.join("kustomize-not-installed")),
            ..KustomizeOptions::default()
        };
        let err = render_error(root, options).await;
        assert!(
            matches!(err, ManifestError::RendererFailed { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains("kustomize"), "{err}");
    }
}
