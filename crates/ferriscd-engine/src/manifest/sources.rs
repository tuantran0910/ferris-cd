//! Multi-source composition (`T20.1`): the declared source list, aliased `$ref` resolution, and the
//! composite deployment revision.
//!
//! # What lives here, and why not in the CRD
//!
//! The CRD crate owns *structure* (`spec.source` vs `spec.sources`, the alias grammar, the entry
//! count cap). This module owns the **composition policy**: which declared source is rendered, which
//! one is a values-only support source, how a `$values/...` reference is resolved inside the
//! referenced worktree, and how per-source revisions collapse into the one string
//! `status.sync.revision` carries. That keeps the CRD crate free of rendering and filesystem
//! concerns and puts the rules where they can be unit-tested against real directories.
//!
//! # The composition rules (deterministic, documented)
//!
//! * `spec.source` (a `v1.0` single-source `Application`) is exactly one declared source, alias
//!   `""`, rendered. Nothing about a single-source `Application` changes.
//! * `spec.sources` is a list. An entry that declares a `renderer` is **rendered** and contributes
//!   its manifests; an entry that declares none is a **support source** — fetched, revision-tracked
//!   and addressable as `$ref`, but contributing no manifests.
//! * When **no** entry declares a `renderer`, the first entry is rendered with `renderer.auto`. A
//!   one-entry `spec.sources` is therefore equivalent to the same `spec.source`.
//! * Rendered entries are concatenated in declaration order. That is the whole "composition":
//!   nothing is merged, reordered, or templated a second time, so two runs of the same revisions
//!   always produce the same bundle (and the same tier-sorted apply order downstream).
//!
//! # Aliases and `$ref`
//!
//! `spec.sources[i].ref: values` makes that source's worktree reachable as `$values/<path>` from
//! any sibling's renderer options — today Helm's `valueFiles`, which is the split-chart pattern the
//! roadmap names (`$values/envs/prod/values.yaml`). Resolution is jailed inside the *referenced*
//! worktree: `..` traversal, an absolute path, a symlink escaping that root, or an unknown alias are
//! all refused, so one tenant's chart can never read outside the sources its own `Application`
//! declared.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ferriscd_crd::{ApplicationSpec, SourceSpec};

use super::cache::sha256_hex;
use super::error::ManifestError;
use super::renderer::encode_fields;

/// Prefix that marks a renderer option as a cross-source reference (`$values/envs/prod.yaml`).
pub const SOURCE_REF_PREFIX: char = '$';

/// Algorithm prefix of a composite deployment identity (`sha256:<64 lowercase hex>`).
///
/// Spelled once so every consumer that abbreviates or recognises a digest agrees: the composite
/// identity of a multi-source deployment and an OCI manifest digest share this shape (`T20.1`).
pub const COMPOSITE_PREFIX: &str = "sha256:";

/// One source a multi-source `Application` declares, normalized for composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredSource {
    /// Alias this source answers to (`""` for `spec.source` or an entry without a `ref`).
    pub alias: String,
    /// The source itself, with `renderer` resolved (`renderer.auto` when the entry omitted it).
    pub spec: SourceSpec,
    /// Whether this source contributes manifests to the bundle.
    pub renders: bool,
}

impl DeclaredSource {
    /// The reference prefix this source answers to (`$alias`), or `None` when it has no alias.
    #[must_use]
    pub fn reference_prefix(&self) -> Option<String> {
        (!self.alias.is_empty()).then(|| format!("{SOURCE_REF_PREFIX}{}", self.alias))
    }
}

/// Normalizes `spec` into the ordered list of declared sources.
///
/// The result is deterministic and total: every accepted `ApplicationSpec` (i.e. one that passed
/// [`ApplicationSpec::validate`]) maps to at least one entry, and the order is the declaration
/// order, which is what `status.sync.revisions` and the render cache key both depend on.
#[must_use]
pub fn declared_sources(spec: &ApplicationSpec) -> Vec<DeclaredSource> {
    if let Some(source) = spec.primary_source() {
        return vec![DeclaredSource {
            alias: String::new(),
            spec: source.clone(),
            renders: true,
        }];
    }
    // `spec.sources`: an explicit `renderer` marks a rendered entry. With no explicit renderer
    // anywhere the first entry is rendered by default, so a one-entry list behaves like `source`.
    let any_renderer = spec.sources.iter().any(|entry| entry.renderer.is_some());
    spec.sources
        .iter()
        .enumerate()
        .map(|(index, entry)| DeclaredSource {
            alias: entry.alias().unwrap_or_default().to_owned(),
            spec: entry.to_source_spec(),
            renders: if any_renderer {
                entry.renderer.is_some()
            } else {
                index == 0
            },
        })
        .collect()
}

/// The aliases `roots` answers to, sorted (`$ref` resolution is a lookup, never a scan).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceRoots {
    roots: Vec<(String, PathBuf)>,
}

impl SourceRoots {
    /// Builds the alias → worktree root map from `(alias, root)` pairs.
    ///
    /// Duplicate aliases are refused: `$values/...` must never resolve to one of two worktrees
    /// depending on iteration order. (`ApplicationSpec::validate` already rejects a duplicate
    /// `ref`, so this is defence in depth for a hand-built spec.)
    ///
    /// Every root is canonicalized here, exactly like the render context's own `root_dir`
    /// ([`super::renderer::RenderContext`] → `canonical_root`): the jail is compared against the
    /// **resolved** path, so a worktree reached through a symlinked prefix (on macOS every
    /// `TempDir` is `/var/...` → `/private/var/...`) must be canonical on both sides of the
    /// comparison, or every legitimate reference would be refused as an escape.
    ///
    /// # Errors
    ///
    /// [`ManifestError::UnsafeReference`] for a duplicated alias, and [`ManifestError::NotFound`] /
    /// [`ManifestError::Io`] when a root cannot be canonicalized.
    pub fn new(roots: impl IntoIterator<Item = (String, PathBuf)>) -> Result<Self, ManifestError> {
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut collected: Vec<(String, PathBuf)> = Vec::new();
        for (alias, root) in roots {
            if alias.is_empty() {
                continue;
            }
            if !seen.insert(alias.clone()) {
                return Err(ManifestError::UnsafeReference {
                    file: "spec.sources".to_owned(),
                    field: "ref".to_owned(),
                    reference: alias,
                    reason:
                        "the ref alias is declared by more than one source, so `$ref/...` would \
                             be ambiguous"
                            .to_owned(),
                });
            }
            collected.push((alias, super::renderer::canonical_root(&root)?));
        }
        collected.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Self { roots: collected })
    }

    /// Whether no source declared an alias.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Canonicalizes the roots and builds the map **off the async worker** (`T20.1`).
    ///
    /// [`Self::new`] performs one `std::fs::canonicalize` per declared source, which is blocking
    /// filesystem work: calling it directly from a reconcile task would park a Tokio worker for as
    /// long as the disk takes (and the roadmap requires every multi-source checkout step to run
    /// inside [`tokio::task::spawn_blocking`]). This is the entry point for async callers; the
    /// verdicts are exactly [`Self::new`]'s.
    ///
    /// # Errors
    ///
    /// Everything [`Self::new`] returns, plus a
    /// [`ManifestError::RendererFailed`] when the blocking task itself panics or is cancelled.
    pub async fn canonicalize(
        roots: impl IntoIterator<Item = (String, PathBuf)>,
    ) -> Result<Self, ManifestError> {
        let roots: Vec<(String, PathBuf)> = roots.into_iter().collect();
        tokio::task::spawn_blocking(move || Self::new(roots))
            .await
            .map_err(|join_err| ManifestError::RendererFailed {
                renderer: "manifest".to_owned(),
                message: format!("source-root canonicalization task failed: {join_err}"),
            })?
    }

    /// The declared aliases, sorted.
    #[must_use]
    pub fn aliases(&self) -> Vec<&str> {
        self.roots.iter().map(|(alias, _)| alias.as_str()).collect()
    }

    /// Whether `reference` is a cross-source reference (`$alias/...`).
    ///
    /// The test is purely lexical: **any** option value that begins with `$` is a reference. A real
    /// file whose name starts with `$` (a `$values.yaml` checked into the chart repository, say) is
    /// therefore *not* addressable as a plain relative path from a renderer option — it is read as a
    /// reference to the alias `values.yaml` and refused as an unknown alias unless such a source
    /// exists. That is deliberate: guessing (`$values/x` → maybe a file, maybe an alias) would make
    /// the same manifest render different values depending on which files happen to exist, and the
    /// failure is loud and names the declared aliases. Quote it as a relative path without the
    /// leading `$` (e.g. `./$values.yaml`) or rename the file.
    #[must_use]
    pub fn is_reference(reference: &str) -> bool {
        reference.trim_start().starts_with(SOURCE_REF_PREFIX)
    }

    /// Resolves `reference` to an absolute path inside the referenced worktree.
    ///
    /// Returns `Ok(None)` when `reference` is not a `$alias/...` reference at all (the caller then
    /// keeps its own single-checkout resolution). A reference that cannot be resolved is an error,
    /// never a fallback: silently reading `$values/x.yaml` as a relative path inside the *chart's*
    /// worktree would render the wrong values file.
    ///
    /// # Errors
    ///
    /// [`ManifestError::UnsafeReference`] for an unknown alias, an escaping path (lexical `..` or a
    /// symlink that leaves the referenced root), and [`ManifestError::NotFound`] for a path that
    /// does not exist.
    pub fn resolve(&self, reference: &str) -> Result<Option<PathBuf>, ManifestError> {
        if !Self::is_reference(reference) {
            return Ok(None);
        }
        let trimmed = reference.trim();
        let without_prefix = trimmed.strip_prefix(SOURCE_REF_PREFIX).unwrap_or(trimmed);
        let (alias, relative) = match without_prefix.split_once('/') {
            Some((alias, relative)) => (alias, relative),
            None => (without_prefix, ""),
        };
        let unsafe_reference = |reason: String| ManifestError::UnsafeReference {
            file: "spec.sources".to_owned(),
            field: "valueFiles".to_owned(),
            reference: trimmed.to_owned(),
            reason,
        };
        let Some((_, root)) = self.roots.iter().find(|(name, _)| name == alias) else {
            return Err(unsafe_reference(format!(
                "unknown source ref '{}'; declared refs are [{}]",
                alias,
                self.aliases().join(", ")
            )));
        };
        if relative.is_empty() {
            return Err(unsafe_reference(
                "the reference must name a file inside the referenced source (e.g. \
                 `$values/envs/prod/values.yaml`)"
                    .to_owned(),
            ));
        }
        if relative.starts_with('/') {
            return Err(unsafe_reference(
                "the reference must be relative to the referenced source root".to_owned(),
            ));
        }
        // `resolve_relative_inside` normalizes lexically, rejects a lexically escaping path, then
        // canonicalizes and proves the *resolved* path (i.e. after symlinks) is still inside root.
        super::renderer::resolve_relative_inside(root.as_path(), root.as_path(), relative)
            .map_err(|error| match error {
                ManifestError::PathEscape { path, .. } => {
                    unsafe_reference(format!("resolves outside the referenced source ('{path}')"))
                }
                other => other,
            })
            .map(Some)
    }
}

/// The deployment identity of a pass over one or more sources.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceRevisions {
    /// Resolved revision of every declared source, in declaration order.
    pub all: Vec<String>,
}

impl SourceRevisions {
    /// Records the ordered per-source revisions.
    #[must_use]
    pub fn new(all: Vec<String>) -> Self {
        Self { all }
    }

    /// The revision a single-source `Application` reports: its one resolved commit.
    #[must_use]
    pub fn single(revision: impl Into<String>) -> Self {
        Self {
            all: vec![revision.into()],
        }
    }

    /// The value `status.sync.revision` carries.
    ///
    /// * One source (`v1.0`, and a one-entry `spec.sources`): **the revision itself**, unchanged —
    ///   this is the `T20.1` trap guard ("never drop `status.sync.revision` compatibility for
    ///   single-source apps"). The existing `sourceChanged` gate, rollback pinning, and every UI
    ///   view keep working byte for byte.
    /// * Several sources: `sha256:<64 hex>` over the length-prefixed ordered list, so a change in
    ///   *any* source moves `revision` and `selfHeal: false` re-syncs (a values-only change is a
    ///   real deployment change). The per-source values stay visible in `status.sync.revisions`.
    #[must_use]
    pub fn composite(&self) -> String {
        match self.all.as_slice() {
            [] => String::new(),
            [single] => single.clone(),
            many => {
                let mut input = String::new();
                let fields: Vec<&str> = many.iter().map(String::as_str).collect();
                encode_fields(&mut input, &fields);
                format!("{COMPOSITE_PREFIX}{}", sha256_hex(input.as_bytes()))
            }
        }
    }

    /// Whether this pass resolves more than one source.
    #[must_use]
    pub fn is_multi_source(&self) -> bool {
        self.all.len() > 1
    }

    /// The per-source revisions to publish in `status.sync.revisions`.
    ///
    /// **One rule, shared with the API**: an `Application` publishes its per-source list exactly
    /// when it *declares* `spec.sources` ([`ApplicationSpec::is_multi_source`]) — the same predicate
    /// the API's `ApplicationSummary.source.multiSource` badge uses, so the badge, the source list
    /// it renders next to, and `status.sync.revisions` can never disagree (`T20.1` finding: a
    /// one-entry `spec.sources` was "multi-source" to the API while publishing no revisions).
    ///
    /// Empty for a `v1.0` `spec.source` `Application`: it must not gain a `/status` field, because
    /// the schema is additive and a stored object has to round-trip unchanged (trap guard `T20.1`).
    #[must_use]
    pub fn published(&self, spec: &ApplicationSpec) -> Vec<String> {
        if spec.is_multi_source() {
            self.all.clone()
        } else {
            Vec::new()
        }
    }

    /// Whether `revision` has the shape [`Self::composite`] produces (`sha256:<64 lowercase hex>`).
    ///
    /// A composite identity is a digest over *several* source revisions, so it can never be resolved
    /// as a Git commit or re-pinned as one source's revision. Callers that must pin a historical
    /// deployment use this to refuse that mistake instead of handing it to a resolver (`T20.1`
    /// finding H2). An OCI manifest digest has the same spelling, so this answers "opaque digest",
    /// not "definitely mine".
    #[must_use]
    pub fn is_composite(revision: &str) -> bool {
        revision
            .strip_prefix(COMPOSITE_PREFIX)
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use ferriscd_crd::{
        ApplicationSpec, GitSourceSpec, HelmRenderer, MultiSourceEntry, OciSourceSpec,
        RendererSpec, SourceSpec, SpecValidationError,
    };
    use tempfile::TempDir;

    use super::*;

    fn write(root: &Path, relative: &str, contents: &str) -> PathBuf {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&path, contents).expect("write fixture file");
        path
    }

    fn git_source(url: &str, revision: &str, path: &str) -> GitSourceSpec {
        GitSourceSpec {
            repo_url: url.to_owned(),
            target_revision: revision.to_owned(),
            path: path.to_owned(),
        }
    }

    fn helm_entry(alias: Option<&str>, url: &str, value_files: &[&str]) -> MultiSourceEntry {
        MultiSourceEntry {
            ref_name: alias.map(str::to_owned),
            git: Some(git_source(url, "main", "charts/api")),
            oci: None,
            renderer: Some(RendererSpec::Helm(HelmRenderer {
                release_name: None,
                value_files: value_files.iter().map(|file| (*file).to_owned()).collect(),
                include_crds: false,
            })),
        }
    }

    fn values_entry(alias: &str, url: &str) -> MultiSourceEntry {
        MultiSourceEntry {
            ref_name: Some(alias.to_owned()),
            git: Some(git_source(url, "main", "")),
            oci: None,
            renderer: None,
        }
    }

    fn spec_with_sources(sources: Vec<MultiSourceEntry>) -> ApplicationSpec {
        serde_json::from_value(serde_json::json!({
            "sources": [],
            "destination": {"namespace": "payments"},
        }))
        .map(|mut spec: ApplicationSpec| {
            spec.sources = sources;
            spec
        })
        .expect("spec must parse")
    }

    /// **Acceptance criterion:** a split chart + values layout renders the chart source and treats
    /// the values source as support-only, in declaration order.
    #[test]
    fn a_chart_plus_values_layout_renders_only_the_chart() {
        let spec = spec_with_sources(vec![
            helm_entry(
                None,
                "https://github.com/example/charts.git",
                &["$values/envs/prod/values.yaml"],
            ),
            values_entry("values", "https://github.com/example/values.git"),
        ]);
        assert!(spec.validate().is_ok());
        let declared = declared_sources(&spec);
        assert_eq!(declared.len(), 2);
        assert!(declared[0].renders, "the chart entry declares a renderer");
        assert_eq!(declared[0].alias, "");
        assert!(!declared[1].renders, "the values entry has no renderer");
        assert_eq!(declared[1].alias, "values");
        assert_eq!(declared[1].reference_prefix().as_deref(), Some("$values"));
        assert_eq!(
            declared[0].spec.repo_url(),
            "https://github.com/example/charts.git"
        );
    }

    /// One `spec.sources` entry with no renderer is equivalent to the same `spec.source`: the first
    /// (only) entry renders with the default renderer.
    #[test]
    fn a_single_entry_without_a_renderer_renders_with_the_default() {
        let entry = MultiSourceEntry {
            ref_name: None,
            git: Some(git_source(
                "https://github.com/example/app.git",
                "main",
                "deploy",
            )),
            oci: None,
            renderer: None,
        };
        let spec = spec_with_sources(vec![entry]);
        assert!(spec.validate().is_ok());
        let declared = declared_sources(&spec);
        assert_eq!(declared.len(), 1);
        assert!(declared[0].renders);
        assert_eq!(declared[0].spec.renderer, RendererSpec::default());
        assert_eq!(declared[0].spec.source_path(), "deploy");
    }

    /// A `v1.0` `spec.source` is one declared source with no alias, and renders.
    #[test]
    fn the_primary_source_is_one_rendered_source() {
        let spec: ApplicationSpec = serde_json::from_value(serde_json::json!({
            "source": {"oci": {"url": "oci://ghcr.io/example/payments", "tag": "1.4.2"}},
            "destination": {"namespace": "payments"},
        }))
        .expect("spec must parse");
        let declared = declared_sources(&spec);
        assert_eq!(declared.len(), 1);
        assert!(declared[0].renders);
        assert!(declared[0].alias.is_empty());
        assert_eq!(
            declared[0].spec.oci_source(),
            Some(&OciSourceSpec {
                url: "oci://ghcr.io/example/payments".to_owned(),
                tag: Some("1.4.2".to_owned()),
                digest: None,
                path: String::new(),
            })
        );
    }

    /// `$values/...` resolves **inside the referenced worktree**, and a `..` escape out of it is
    /// refused (acceptance criterion: "`$values/...` resolution succeeds inside the referenced repo
    /// and rejects `../` escapes").
    #[test]
    fn a_reference_resolves_inside_the_referenced_root_and_rejects_traversal() {
        let chart = TempDir::new().expect("chart tempdir");
        let values = TempDir::new().expect("values tempdir");
        let expected = write(values.path(), "envs/prod/values.yaml", "replicaCount: 3\n");
        let roots = SourceRoots::new(vec![
            (
                "values".to_owned(),
                std::fs::canonicalize(values.path()).expect("canonical"),
            ),
            (
                "chart".to_owned(),
                std::fs::canonicalize(chart.path()).expect("canonical"),
            ),
        ])
        .expect("roots");

        assert!(!roots.is_empty());
        assert_eq!(roots.aliases(), vec!["chart", "values"]);
        assert_eq!(
            roots
                .resolve("$values/envs/prod/values.yaml")
                .expect("resolves"),
            Some(std::fs::canonicalize(expected).expect("canonical"))
        );

        // Not a reference at all: the caller keeps its own single-checkout resolution.
        assert_eq!(roots.resolve("values.yaml").expect("not a ref"), None);
        assert_eq!(
            roots.resolve("envs/prod/values.yaml").expect("not a ref"),
            None
        );

        // `..` out of the referenced root, an absolute path, and an unknown alias are all refused.
        for (reference, expected_fragment) in [
            ("$values/../../etc/passwd", "outside the referenced source"),
            (
                "$values/envs/../../../secret.yaml",
                "outside the referenced source",
            ),
            ("$values//etc/passwd", "must be relative"),
            (
                "$missing/envs/prod/values.yaml",
                "unknown source ref 'missing'",
            ),
            ("$values", "must name a file"),
        ] {
            match roots.resolve(reference) {
                Err(ManifestError::UnsafeReference { reason, .. }) => {
                    assert!(
                        reason.contains(expected_fragment),
                        "{reference}: {reason} does not mention {expected_fragment}"
                    );
                }
                other => panic!("{reference} must be refused, got {other:?}"),
            }
        }

        // A path that is inside the root but does not exist is `NotFound`, never a silent `None`.
        assert!(matches!(
            roots.resolve("$values/envs/missing.yaml"),
            Err(ManifestError::NotFound { .. })
        ));
    }

    /// A symlink inside the referenced worktree that points outside it is refused: the jail is on
    /// the *resolved* path, not on the textual one.
    #[cfg(unix)]
    #[test]
    fn a_symlink_escaping_the_referenced_root_is_rejected() {
        let values = TempDir::new().expect("values tempdir");
        let outside = TempDir::new().expect("outside tempdir");
        let secret = write(outside.path(), "secret.yaml", "password: hunter2\n");
        std::os::unix::fs::symlink(&secret, values.path().join("linked.yaml"))
            .expect("create symlink");
        let roots = SourceRoots::new(vec![(
            "values".to_owned(),
            std::fs::canonicalize(values.path()).expect("canonical"),
        )])
        .expect("roots");

        match roots.resolve("$values/linked.yaml") {
            Err(ManifestError::PathEscape { .. } | ManifestError::UnsafeReference { .. }) => {}
            other => panic!("a symlink escaping the source root must be refused, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_aliases_are_refused() {
        // A real root, so the verdict can only come from the duplicate alias and never from a
        // non-existent directory (roots are canonicalized before they are stored).
        let root = TempDir::new().expect("tempdir");
        let path = std::fs::canonicalize(root.path()).expect("canonical");
        let error = SourceRoots::new(vec![
            ("values".to_owned(), path.clone()),
            ("values".to_owned(), path),
        ])
        .expect_err("a duplicate alias must be refused");
        assert!(error.to_string().contains("ambiguous"), "{error}");
    }

    /// The composite revision: one source keeps its commit SHA verbatim (trap guard), several
    /// sources collapse into a stable digest that moves when any of them moves.
    #[test]
    fn the_composite_revision_is_the_commit_for_one_source_and_a_digest_for_many() {
        let v1: ApplicationSpec = serde_json::from_value(serde_json::json!({
            "source": {"git": {"repoURL": "https://example.com/r.git"}},
            "destination": {"namespace": "payments"},
        }))
        .expect("spec must parse");
        let single = SourceRevisions::single("0123456789abcdef0123456789abcdef01234567");
        assert_eq!(
            single.composite(),
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert!(!single.is_multi_source());
        assert!(
            single.published(&v1).is_empty(),
            "a single-source Application must not gain a status.sync.revisions field"
        );

        let multi = SourceRevisions::new(vec!["chart-sha".to_owned(), "values-sha".to_owned()]);
        assert!(multi.is_multi_source());
        let spec = spec_with_sources(vec![
            values_entry("chart", "https://example.com/a.git"),
            values_entry("values", "https://example.com/b.git"),
        ]);
        assert_eq!(multi.published(&spec), multi.all);
        let composite = multi.composite();
        assert!(composite.starts_with("sha256:"), "{composite}");
        assert_eq!(composite.len(), "sha256:".len() + 64);
        assert_eq!(
            composite,
            multi.composite(),
            "the composite revision must be deterministic"
        );
        assert!(
            SourceRevisions::is_composite(&composite),
            "a composite must be recognizable as one: {composite}"
        );

        // Any move — the first source, the second source, the order — changes the identity.
        for variant in [
            SourceRevisions::new(vec!["chart-sha2".to_owned(), "values-sha".to_owned()]),
            SourceRevisions::new(vec!["chart-sha".to_owned(), "values-sha2".to_owned()]),
            SourceRevisions::new(vec!["values-sha".to_owned(), "chart-sha".to_owned()]),
        ] {
            assert_ne!(variant.composite(), composite);
        }

        // No source at all is not a digest of nothing: it is the empty revision, which the decision
        // gate already treats as "unresolved".
        assert_eq!(SourceRevisions::default().composite(), "");
        assert!(!SourceRevisions::is_composite(""));
        // A commit SHA is not composite, and neither is a near-miss digest: the shape is exact.
        assert!(!SourceRevisions::is_composite(
            "0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(!SourceRevisions::is_composite(
            &composite.replace("sha256:", "")
        ));
        assert!(!SourceRevisions::is_composite(&format!("{composite}0")));
        assert!(!SourceRevisions::is_composite(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"
        ));
    }

    /// **`T20.1` finding (M8).** Publishing the per-source list is decided by the **declaration**
    /// (`spec.sources`), not by the number of resolved revisions: a one-entry `spec.sources`
    /// `Application` reports one revision, so the API's `multi_source` badge, the `sources` list it
    /// renders beside it, and `status.sync.revisions` all agree.
    #[test]
    fn a_one_entry_source_list_publishes_its_single_revision() {
        let spec = spec_with_sources(vec![values_entry(
            "values",
            "https://example.com/values.git",
        )]);
        assert!(spec.is_multi_source(), "it declares spec.sources");
        let revisions = SourceRevisions::new(vec!["commit-sha".to_owned()]);
        assert!(!revisions.is_multi_source(), "one resolved revision");
        assert_eq!(
            revisions.composite(),
            "commit-sha",
            "one source keeps its revision verbatim, exactly like spec.source"
        );
        assert_eq!(
            revisions.published(&spec),
            vec!["commit-sha".to_owned()],
            "a one-entry spec.sources must publish its revision like the API's sources list"
        );

        // The `v1.0` shape still publishes nothing, which is what keeps a stored object
        // byte-identical — even if the resolved list somehow carries one entry.
        let v1: ApplicationSpec = serde_json::from_value(serde_json::json!({
            "source": {"git": {"repoURL": "https://example.com/r.git"}},
            "destination": {"namespace": "payments"},
        }))
        .expect("spec must parse");
        assert!(!v1.is_multi_source());
        assert!(revisions.published(&v1).is_empty());
    }

    /// The async constructor is the one a reconcile task may call: it canonicalizes off the worker
    /// (a blocking `canonicalize` on a Tokio worker is exactly what the roadmap forbids) and returns
    /// the same verdicts as [`SourceRoots::new`].
    #[tokio::test]
    async fn canonicalizing_roots_off_the_worker_resolves_references() {
        let values = TempDir::new().expect("values tempdir");
        let expected = write(values.path(), "values.yaml", "replicaCount: 3\n");
        let roots = SourceRoots::canonicalize(vec![
            ("values".to_owned(), values.path().to_path_buf()),
            (String::new(), values.path().to_path_buf()),
        ])
        .await
        .expect("roots");
        assert_eq!(roots.aliases(), vec!["values"]);
        assert_eq!(
            roots.resolve("$values/values.yaml").expect("resolves"),
            Some(std::fs::canonicalize(expected).expect("canonical"))
        );

        // The duplicate-alias verdict is the same one `SourceRoots::new` reports.
        let duplicate = SourceRoots::canonicalize(vec![
            ("values".to_owned(), values.path().to_path_buf()),
            ("values".to_owned(), values.path().to_path_buf()),
        ])
        .await
        .expect_err("a duplicate alias must be refused");
        assert!(duplicate.to_string().contains("ambiguous"), "{duplicate}");
    }

    /// The cap and the mutual exclusion are visible offline, with the exact error the CEL rule
    /// reports (trap guard: "enforce `sources.len() <= 16` in both CEL and offline validation").
    #[test]
    fn validation_caps_the_list_and_enforces_the_exclusive_declaration() {
        let mut too_many = spec_with_sources(
            (0..=16)
                .map(|index| values_entry(&format!("ref-{index}"), "https://example.com/r.git"))
                .collect(),
        );
        assert_eq!(
            too_many.validate(),
            Err(SpecValidationError::TooManySources { count: 17 })
        );
        too_many.sources.truncate(16);
        assert!(
            too_many.validate().is_ok(),
            "16 entries is the accepted maximum"
        );

        let mut both = spec_with_sources(vec![values_entry("values", "https://example.com/r.git")]);
        both.source = Some(SourceSpec::default());
        assert_eq!(
            both.validate(),
            Err(SpecValidationError::ConflictingSourceDeclaration)
        );

        let mut neither = spec_with_sources(Vec::new());
        neither.source = None;
        assert_eq!(
            neither.validate(),
            Err(SpecValidationError::MissingSourceDeclaration)
        );

        // Per-entry exactly-one-of, duplicate refs, and the alias grammar.
        let empty_entry = spec_with_sources(vec![MultiSourceEntry::default()]);
        assert_eq!(
            empty_entry.validate(),
            Err(SpecValidationError::MissingMultiSourceReference { index: 0 })
        );

        let ambiguous = spec_with_sources(vec![MultiSourceEntry {
            ref_name: Some("values".to_owned()),
            git: Some(git_source("https://example.com/r.git", "main", "")),
            oci: Some(OciSourceSpec {
                url: "oci://ghcr.io/example/chart".to_owned(),
                tag: Some("1.0.0".to_owned()),
                digest: None,
                path: String::new(),
            }),
            renderer: None,
        }]);
        assert_eq!(
            ambiguous.validate(),
            Err(SpecValidationError::AmbiguousMultiSourceReference { index: 0 })
        );

        let duplicate = spec_with_sources(vec![
            values_entry("values", "https://example.com/a.git"),
            values_entry("values", "https://example.com/b.git"),
        ]);
        assert_eq!(
            duplicate.validate(),
            Err(SpecValidationError::DuplicateSourceRef {
                name: "values".to_owned()
            })
        );

        // The alias grammar: a DNS-1123 label, so a `$ref/...` path segment is never ambiguous.
        for rejected in [
            ".", "..", "Values", "va/lues", "-values", "values-", "va lues",
        ] {
            let spec = spec_with_sources(vec![values_entry(rejected, "https://example.com/a.git")]);
            match spec.validate() {
                Err(SpecValidationError::InvalidSourceRef { value, reason }) => {
                    assert_eq!(value, rejected);
                    assert!(!reason.is_empty());
                }
                other => panic!("ref {rejected:?} must be refused, got {other:?}"),
            }
        }
        for accepted in ["values", "v1", "team-values", "a1"] {
            let spec = spec_with_sources(vec![values_entry(accepted, "https://example.com/a.git")]);
            assert_eq!(spec.validate(), Ok(()), "ref {accepted:?} must be accepted");
        }
        // A blank `ref` is not a typo to refuse: it is "this source has no alias", which is exactly
        // what an omitted `ref` means, and a padded one is trimmed to its label.
        let unaliased = spec_with_sources(vec![values_entry("", "https://example.com/a.git")]);
        assert_eq!(unaliased.validate(), Ok(()));
        assert_eq!(declared_sources(&unaliased)[0].alias, "");
        let padded = spec_with_sources(vec![values_entry(
            "  values  ",
            "https://example.com/a.git",
        )]);
        assert_eq!(padded.validate(), Ok(()));
        assert_eq!(declared_sources(&padded)[0].alias, "values");
    }

    /// A `spec.sources` entry carrying only `oci` is accepted and renders when it declares a
    /// renderer — the split OCI-chart + Git-values layout from the roadmap's `kind` experiment.
    #[test]
    fn an_oci_chart_with_a_git_values_source_is_accepted() {
        let spec = spec_with_sources(vec![
            MultiSourceEntry {
                ref_name: None,
                git: None,
                oci: Some(OciSourceSpec {
                    url: "oci://localhost:5000/example/api".to_owned(),
                    tag: Some("1.4.2".to_owned()),
                    digest: None,
                    path: String::new(),
                }),
                renderer: Some(RendererSpec::Helm(HelmRenderer {
                    release_name: Some("api".to_owned()),
                    value_files: vec!["$values/envs/prod/values.yaml".to_owned()],
                    include_crds: false,
                })),
            },
            values_entry("values", "https://github.com/example/values.git"),
        ]);
        assert!(spec.validate().is_ok());
        let declared = declared_sources(&spec);
        assert!(declared[0].renders);
        assert_eq!(
            declared[0].spec.repo_url(),
            "oci://localhost:5000/example/api"
        );
        assert!(!declared[1].renders);
        assert_eq!(
            declared[1].spec.repo_url(),
            "https://github.com/example/values.git"
        );
    }
}
