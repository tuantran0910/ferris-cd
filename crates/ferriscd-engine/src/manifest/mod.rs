//! Manifest engine: multi-document YAML 1.2 parsing, safe directory loading, offline
//! normalization of desired Kubernetes objects, and the ecosystem renderers (Kustomize v5,
//! Helm v4) that feed all of the above.
//!
//! Plain pipeline: [`loader::load`] -> [`yaml::parse_file`] -> [`normalize::normalize`].
//!
//! Renderer pipeline: [`renderer::RenderContext`] -> [`renderer::ManifestRenderer::render`]
//! (plain YAML, `kustomize build`, or `helm template`, the latter two sandboxed by [`exec`]) ->
//! [`renderer::parse_and_normalize`] -> [`types::DesiredResource`].
//!
//! [`cache::RenderPipeline`] adds a collision-free LRU in front of the renderer pipeline so a
//! periodic requeue at an unchanged commit costs a hash lookup instead of a subprocess.

pub mod cache;
pub mod error;
pub mod exec;
#[cfg(test)]
mod fake_runner;
pub mod helm;
pub mod kustomize;
pub mod loader;
pub mod normalize;
pub mod renderer;
pub mod types;
pub mod yaml;

pub use cache::{
    DEFAULT_CACHE_CAPACITY, RenderCache, RenderCacheKey, RenderCacheStats, RenderPipeline,
};
pub use error::ManifestError;
pub use exec::{DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_TIMEOUT, ExecError, SandboxedCommand};
pub use helm::{HelmOptions, HelmRenderer};
pub use kustomize::{KustomizeOptions, KustomizeRenderer};
pub use loader::{ManifestFile, ManifestLoaderConfig, load};
pub use normalize::{check_duplicate_keys, normalize};
pub use renderer::{
    ManifestRenderer, PlainYamlOptions, PlainYamlRenderer, RenderContext, RendererBinaries,
    RendererConfig, RendererKind, detect_renderer, parse_and_normalize, redact_repo_url, render,
    render_desired,
};
pub use types::{DesiredResource, GroupVersionKind, ResourceKey};
pub use yaml::parse_file;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::TempDir;

    use super::*;
    use crate::graph::sort_by_tier;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write fixture file");
    }

    #[test]
    fn pipeline_load_parse_normalize_sort_composes_and_surfaces_bad_docs() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path();

        write(
            root,
            "good/00-namespace.yaml",
            "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: demo\n",
        );
        write(
            root,
            "good/10-crd.yaml",
            "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: widgets.example.com\nspec:\n  group: example.com\n  names:\n    kind: Widget\n    plural: widgets\n  scope: Namespaced\n  versions:\n    - name: v1\n      served: true\n      storage: true\n      schema:\n        openAPIV3Schema:\n          type: object\n",
        );
        write(
            root,
            "good/20-configmap.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: app-config\n",
        );
        write(
            root,
            "good/30-deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n",
        );
        write(
            root,
            "good/40-list.yaml",
            "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: ConfigMap\n    metadata:\n      name: from-list\n",
        );

        let files = load(root, "good", &ManifestLoaderConfig::default()).expect("load good");
        let mut resources = Vec::new();
        for file in files {
            resources.extend(parse_file(&file.source_file, &file.contents).expect("parse good"));
        }
        let normalized = normalize(resources).expect("normalize");
        let sorted = sort_by_tier(normalized);

        let order: Vec<(&str, &str)> = sorted
            .iter()
            .map(|r| (r.gvk.kind.as_str(), r.key.name.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                ("Namespace", "demo"),
                ("CustomResourceDefinition", "widgets.example.com"),
                ("ConfigMap", "app-config"),
                ("ConfigMap", "from-list"),
                ("Deployment", "app"),
            ]
        );

        // A bad document in its own file must fail the same pipeline with file + 1-based index.
        write(
            root,
            "bad.yaml",
            "apiVersion: v1\nmetadata:\n  name: missing-kind\n",
        );
        let files = load(root, "bad.yaml", &ManifestLoaderConfig::default()).expect("load bad");
        let err = parse_file(&files[0].source_file, &files[0].contents).expect_err("bad doc");
        let text = err.to_string();
        assert!(text.contains("bad.yaml"), "{text}");
        assert!(text.contains("document 1"), "{text}");
        assert!(text.contains("kind"), "{text}");
    }
}
