//! The four `ApplicationSet` generators (`T19.3`).
//!
//! | Generator | Input | Reused seam |
//! |---|---|---|
//! | `list` | static key/value maps | none (pure) |
//! | `clusters` | label selector over registered cluster registrations | [`ClusterParamSource`] (controller: `ClusterManager`) |
//! | `git` | directory glob or parameter-file glob at one commit | [`GitParameterSource`] (controller: `RepoCache` + `sanitize_worktree`) + [`crate::manifest::parse_document`] budgets |
//! | `matrix` | Cartesian product of exactly two leaf generators | the three above, under the fan-out cap |
//!
//! # Why the sources are traits
//!
//! Two of the generators need something the pure engine must not own: a Git checkout and the
//! cluster registry. Both are injected as narrow traits, which keeps this module free of `gix`,
//! `kube`, and network access — and makes every generator testable with an in-memory fake (no
//! sleeps, no repository, no cluster).
//!
//! # Determinism
//!
//! Every generator returns a deterministic order, independent of `readdir` or `HashMap` iteration:
//! `list` keeps the declared element order, `clusters` sorts by cluster name, `git` sorts the
//! matched directory/file paths lexicographically, and `matrix` iterates the left generator first
//! (left-major, right-minor). On a parameter-key collision inside a matrix the **right** (later)
//! generator wins, deterministically. The final rendered list is sorted by `Application` name, so
//! the whole plan is byte-stable for the same inputs.
//!
//! # Bounded work
//!
//! A `git` generator never reads an unbounded directory tree or an unbounded file: the walk is
//! capped at [`MAX_GIT_WALK_ENTRIES`], every parameter file at [`MAX_PARAMETER_FILE_BYTES`], glob
//! matching at [`MAX_GLOB_CELLS`] (a `**` chain is matched with a segment table, never by
//! re-walking the suffixes recursively), and both the per-generator and the total expansion at the
//! effective fan-out cap — including *inside* the parameter-file branch, where one file may hold a
//! whole sequence of parameter sets.
//!
//! # Blocking I/O
//!
//! The Git checkout is awaited (the backend already runs its disk/network work in
//! `spawn_blocking`), and the directory walk, file reads, and YAML parsing all run inside
//! [`tokio::task::spawn_blocking`], so a slow disk never blocks an async worker.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ferriscd_crd::applicationset::{
    ApplicationSetGenerator, ClusterGenerator, GitDirectoryPattern, GitFilePattern, GitGenerator,
    ListGenerator, MatrixChildGenerator, MatrixGenerator, is_valid_parameter_key,
};
use serde_json::Value;

use crate::manifest::parse_document;
use crate::policy::wildcard_matches;
use crate::repo::{RepoCheckout, RepoFuture};

use super::template::sanitize_dns1123;
use super::{ApplicationSetError, MAX_GENERATED_APPS};

/// Hard ceiling on how many directory entries one `git` generator may walk.
///
/// The worktree is untrusted input: a repository that ships a hundred thousand directories must not
/// turn one `ApplicationSet` reconcile into an unbounded disk scan. Exceeding the budget is a
/// **terminal** [`ApplicationSetError::WalkBudgetExceeded`], never a silent partial result (and
/// never retried: the same repository will not shrink).
pub const MAX_GIT_WALK_ENTRIES: usize = 20_000;

/// Hard ceiling on the size of one Git generator parameter file.
pub const MAX_PARAMETER_FILE_BYTES: u64 = 1024 * 1024;

/// One generator's parameter map: flat `key -> value`, `BTreeMap` for deterministic iteration.
pub type ParamMap = BTreeMap<String, String>;

/// One registered cluster as the `clusters` generator sees it.
///
/// Deliberately credential-free: the name, the `Secret`'s labels (for the selector), and the
/// optional default namespace. No API server URL, token, or CA ever reaches a generator parameter,
/// so nothing can leak into a generated `Application`'s spec or `/status`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClusterRegistration {
    /// Cluster name (the `spec.destination.cluster` value).
    pub name: String,
    /// Labels of the cluster-registration `Secret`.
    pub labels: BTreeMap<String, String>,
    /// The registration's default namespace, when it sets one.
    pub default_namespace: Option<String>,
}

impl ClusterRegistration {
    /// Builds a registration.
    #[must_use]
    pub fn new(name: impl Into<String>, labels: BTreeMap<String, String>) -> Self {
        Self {
            name: name.into(),
            labels,
            default_namespace: None,
        }
    }

    /// Sets the registration's default namespace.
    #[must_use]
    pub fn with_default_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.default_namespace = Some(namespace.into());
        self
    }
}

/// The cluster registry, as the `clusters` generator consumes it.
///
/// The controller implements this over `ClusterManager::names()` and the lifecycle-tracked labels,
/// so the generator always sees the registry's authoritative, sorted snapshot and never reads a
/// cluster `Secret` itself.
pub trait ClusterParamSource: Send + Sync {
    /// Every registered (non-`in-cluster`) cluster.
    fn clusters(&self) -> Vec<ClusterRegistration>;
}

/// A Git checkout, as the `git` generator consumes it.
///
/// The controller implements this with `RepoCache` (which materializes the worktree and runs
/// `sanitize_worktree` before publishing it) and the credentials resolved from
/// `ferriscd.io/secret-type=repository` `Secret`s. The returned [`RepoCheckout`] keeps its lease
/// alive for as long as the generator holds it.
pub trait GitParameterSource: Send + Sync {
    /// Materializes `repo_url` at `revision` and returns the immutable checkout.
    fn checkout<'a>(&'a self, repo_url: &'a str, revision: &'a str)
    -> RepoFuture<'a, RepoCheckout>;
}

/// Everything one generator expansion needs.
pub struct GeneratorContext<'a> {
    /// The cluster registry.
    pub clusters: &'a dyn ClusterParamSource,
    /// The Git checkout seam.
    pub git: &'a dyn GitParameterSource,
    /// The effective fan-out cap for this `ApplicationSet` (`<= MAX_GENERATED_APPS`).
    pub limit: usize,
}

impl<'a> GeneratorContext<'a> {
    /// Builds a context, clamping `limit` to the hard maximum.
    #[must_use]
    pub fn new(
        clusters: &'a dyn ClusterParamSource,
        git: &'a dyn GitParameterSource,
        limit: usize,
    ) -> Self {
        Self {
            clusters,
            git,
            limit: limit.min(MAX_GENERATED_APPS),
        }
    }
}

/// Expands one (already validated) generator into its parameter sets.
///
/// # Errors
///
/// [`ApplicationSetError::FanOutLimitExceeded`] when the expansion exceeds
/// [`GeneratorContext::limit`], [`ApplicationSetError::Generator`] when a source fails, and
/// [`ApplicationSetError::ParameterFile`] when a Git parameter file is unusable.
pub async fn expand(
    context: &GeneratorContext<'_>,
    generator: &ApplicationSetGenerator,
) -> Result<Vec<ParamMap>, ApplicationSetError> {
    match generator {
        // A `matrix` is the only composite generator, and its children are `MatrixChildGenerator`
        // values (no nesting is representable), so this dispatch is not recursive.
        ApplicationSetGenerator::Matrix(matrix) => expand_matrix(context, matrix).await,
        ApplicationSetGenerator::List(list) => expand_list(context.limit, list),
        ApplicationSetGenerator::Clusters(clusters) => expand_clusters_capped(context, clusters),
        ApplicationSetGenerator::Git(git) => expand_git(context, git).await,
    }
}

/// One matrix child, expanded exactly like a top-level leaf generator.
async fn expand_child(
    context: &GeneratorContext<'_>,
    generator: &MatrixChildGenerator,
) -> Result<Vec<ParamMap>, ApplicationSetError> {
    match generator {
        MatrixChildGenerator::List(list) => expand_list(context.limit, list),
        MatrixChildGenerator::Clusters(clusters) => expand_clusters_capped(context, clusters),
        MatrixChildGenerator::Git(git) => expand_git(context, git).await,
    }
}

fn expand_clusters_capped(
    context: &GeneratorContext<'_>,
    clusters: &ClusterGenerator,
) -> Result<Vec<ParamMap>, ApplicationSetError> {
    let params = expand_clusters(context, clusters);
    enforce_limit(params.len(), context.limit)?;
    Ok(params)
}

/// Enforces the effective cap, refusing (never truncating) an over-cap expansion.
fn enforce_limit(requested: usize, limit: usize) -> Result<(), ApplicationSetError> {
    if requested > limit {
        return Err(ApplicationSetError::FanOutLimitExceeded {
            requested,
            limit,
            hard_limit: MAX_GENERATED_APPS,
        });
    }
    Ok(())
}

fn expand_list(limit: usize, list: &ListGenerator) -> Result<Vec<ParamMap>, ApplicationSetError> {
    enforce_limit(list.elements.len(), limit)?;
    Ok(list.elements.clone())
}

/// Whether `registration` satisfies every `matchLabels` entry (exact match, all of them).
fn matches_selector(
    selection: &ferriscd_crd::applicationset::ClusterSelector,
    registration: &ClusterRegistration,
) -> bool {
    selection.match_labels.iter().all(|(key, value)| {
        registration
            .labels
            .get(key)
            .is_some_and(|actual| actual == value)
    })
}

fn expand_clusters(context: &GeneratorContext<'_>, generator: &ClusterGenerator) -> Vec<ParamMap> {
    build_cluster_params(context.clusters.clusters(), generator)
}

/// Turns a cluster snapshot into parameter sets; split out so the pure part is unit-testable
/// without a [`GeneratorContext`].
fn build_cluster_params(
    mut registrations: Vec<ClusterRegistration>,
    generator: &ClusterGenerator,
) -> Vec<ParamMap> {
    registrations.sort_by(|left, right| left.name.cmp(&right.name));
    registrations.dedup_by(|later, earlier| later.name == earlier.name);
    registrations
        .into_iter()
        .filter(|registration| {
            generator
                .selector
                .as_ref()
                .is_none_or(|selector| matches_selector(selector, registration))
        })
        .map(|registration| {
            let mut params = ParamMap::new();
            params.insert("name".to_owned(), registration.name.clone());
            params.insert("cluster.name".to_owned(), registration.name.clone());
            if let Some(namespace) = &registration.default_namespace {
                params.insert("cluster.defaultNamespace".to_owned(), namespace.clone());
            }
            for (key, value) in &registration.labels {
                params.insert(format!("metadata.labels.{key}"), value.clone());
            }
            params
        })
        .collect()
}

async fn expand_matrix(
    context: &GeneratorContext<'_>,
    matrix: &MatrixGenerator,
) -> Result<Vec<ParamMap>, ApplicationSetError> {
    let [left, right] = matrix.generators.as_slice() else {
        // Arity is a property of the spec, so no retry can fix it (and `validate` rejects it first).
        return Err(ApplicationSetError::generator(
            "matrix",
            format!(
                "a matrix generator needs exactly two children, got {}",
                matrix.generators.len()
            ),
            false,
        ));
    };
    let left_params = Box::pin(expand_child(context, left)).await?;
    let right_params = Box::pin(expand_child(context, right)).await?;
    // Refuse the product *before* materializing it: a fan-out bomb is a multiplication, and
    // allocating the intermediate vectors first would already be the denial of service.
    let product = left_params.len().checked_mul(right_params.len()).ok_or(
        ApplicationSetError::FanOutLimitExceeded {
            requested: usize::MAX,
            limit: context.limit,
            hard_limit: MAX_GENERATED_APPS,
        },
    )?;
    enforce_limit(product, context.limit)?;
    let mut combined = Vec::with_capacity(product);
    for left in &left_params {
        for right in &right_params {
            let mut merged = left.clone();
            // Right wins on a collision, deterministically (documented in the module docs).
            merged.extend(
                right
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            combined.push(merged);
        }
    }
    Ok(combined)
}

async fn expand_git(
    context: &GeneratorContext<'_>,
    generator: &GitGenerator,
) -> Result<Vec<ParamMap>, ApplicationSetError> {
    let checkout = context
        .git
        .checkout(&generator.repo_url, &generator.revision)
        .await
        // The retry classification travels with the error: a dropped connection is worth another
        // pass, a repository whose credentials are rejected (or a revision that does not exist) is
        // not. Reporting every Git failure as retryable is what finding H2 fixed.
        .map_err(|err| {
            ApplicationSetError::generator(
                "git",
                format!("could not check out the requested revision: {err}"),
                err.is_retryable(),
            )
        })?;
    let root = checkout.root_dir().to_path_buf();
    let directories = generator.directories.clone();
    let files = generator.files.clone();
    let limit = context.limit;
    // The whole walk/parse is synchronous disk work: keep it off the async workers.
    tokio::task::spawn_blocking(move || expand_git_blocking(&root, &directories, &files, limit))
        .await
        // A `spawn_blocking` join failure is a cancelled or panicking worker, never a verdict about
        // the repository: retryable.
        .map_err(|err| {
            ApplicationSetError::generator(
                "git",
                format!("the parameter evaluation task failed: {err}"),
                true,
            )
        })?
}

/// Synchronous (blocking) Git parameter evaluation over one sanitized worktree.
fn expand_git_blocking(
    root: &Path,
    directories: &[GitDirectoryPattern],
    files: &[GitFilePattern],
    limit: usize,
) -> Result<Vec<ParamMap>, ApplicationSetError> {
    let entries = walk_worktree(root)?;

    if !directories.is_empty() {
        let mut matched: Vec<&str> = entries
            .iter()
            .filter(|entry| entry.is_dir)
            .map(|entry| entry.path.as_str())
            .filter(|path| {
                is_selected(
                    path,
                    directories
                        .iter()
                        .map(|pattern| (pattern.path.as_str(), pattern.exclude)),
                )
            })
            .collect();
        matched.sort_unstable();
        enforce_limit(matched.len(), limit)?;
        return Ok(matched.into_iter().map(path_params).collect());
    }

    let mut matched: Vec<&str> = entries
        .iter()
        .filter(|entry| !entry.is_dir)
        .map(|entry| entry.path.as_str())
        .filter(|path| {
            is_selected(
                path,
                files
                    .iter()
                    .map(|pattern| (pattern.path.as_str(), pattern.exclude)),
            )
        })
        .collect();
    matched.sort_unstable();
    enforce_limit(matched.len(), limit)?;

    let mut params = Vec::with_capacity(matched.len());
    for path in matched {
        let absolute = root.join(path);
        let document = read_parameter_file(&absolute, path)?;
        let parsed: Value =
            parse_document(&document).map_err(|err| ApplicationSetError::ParameterFile {
                path: path.to_owned(),
                message: format!(
                    "not a usable YAML/JSON parameter document under the parser budgets ({err})"
                ),
            })?;
        params.extend(params_from_document(&parsed, path)?);
        // The cap is enforced *inside* the file branch too: one parameter file may hold a sequence,
        // so a handful of matched files can be far more parameter sets than the number of files.
        // Checking per file keeps the refusal from materializing an over-cap fleet first.
        enforce_limit(params.len(), limit)?;
    }
    Ok(params)
}

/// Whether `path` is selected by an include/exclude pattern list.
///
/// Exclusions always win (Argo semantics): a path matching an include **and** an exclude is out.
fn is_selected<'a>(path: &str, patterns: impl Iterator<Item = (&'a str, bool)>) -> bool {
    let mut included = false;
    for (pattern, exclude) in patterns {
        if glob_matches(pattern.trim(), path) {
            if exclude {
                return false;
            }
            included = true;
        }
    }
    included
}

/// Matches a repository-relative `path` against a segment-based glob.
///
/// `*`/`?` match inside one segment (via [`wildcard_matches`]), and a `**` segment matches **zero or
/// more** whole segments. Matching is case-sensitive, like Git and Kubernetes.
///
/// # Why this is a table and not a recursion
///
/// The obvious recursive `**` matcher re-derives the same `(pattern, path)` suffixes over and over,
/// so a pattern with *k* `**` segments costs `O(path_segments^k)` — a hostile (or merely sloppy)
/// `**/**/**/…/x` pattern pins a reconcile thread with no allocation and no I/O to show for it.
/// This walks the (pattern index × path index) table once, back to front, so the cost is
/// `O(pattern_segments × path_segments)`. Two rows of `path.len() + 1` booleans are all the state
/// that is needed, so the bound is on **time**, not on memory.
///
/// [`MAX_GLOB_CELLS`] caps that product. It is far above anything an author can write by accident
/// (`2^20` cells is a 1024-segment pattern against a 1024-segment path), and a pattern/path pair
/// that exceeds it is treated as **not matching**: the walk simply yields fewer parameter sets
/// instead of blocking the controller. Refusing a match that no sane glob needs is the safe
/// direction for a generator that feeds a fleet.
#[must_use]
pub fn glob_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let path: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    match_segments(&pattern, &path)
}

/// Hard ceiling on the `pattern × path` segment table one match may build.
///
/// See [`glob_matches`]: exceeding it is a *no match*, never an error and never unbounded work.
pub const MAX_GLOB_CELLS: usize = 1 << 20;

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    // `m[i][j]` = "does `pattern[i..]` match `path[j..]`?", computed with two rows: `next` is row
    // `i + 1`, `current` is the row being filled.
    let cells = pattern
        .len()
        .saturating_add(1)
        .saturating_mul(path.len().saturating_add(1));
    if cells > MAX_GLOB_CELLS {
        return false;
    }
    let mut next = vec![false; path.len() + 1];
    // `m[pattern.len()][path.len()]` is the empty-suffix match; everything else in that row is false.
    next[path.len()] = true;
    let mut current = vec![false; path.len() + 1];
    for segment in pattern.iter().rev() {
        if *segment == "**" {
            // `**` matches zero segments (`next[j]`) or one more (`current[j + 1]`, already computed
            // because `j` descends) — including the empty suffix, where it matches zero.
            current[path.len()] = next[path.len()];
            for index in (0..path.len()).rev() {
                current[index] = next[index] || current[index + 1];
            }
        } else {
            // A literal/wildcard segment consumes exactly one path segment.
            current[path.len()] = false;
            for index in (0..path.len()).rev() {
                current[index] = wildcard_matches(segment, path[index]) && next[index + 1];
            }
        }
        std::mem::swap(&mut next, &mut current);
    }
    next[0]
}

/// Directory parameters: `path`, `path.basename`, `path[i]`, `path.basenameNormalized`.
fn path_params(path: &str) -> ParamMap {
    let mut params = ParamMap::new();
    params.insert("path".to_owned(), path.to_owned());
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    for (index, segment) in segments.iter().enumerate() {
        params.insert(format!("path[{index}]"), (*segment).to_owned());
    }
    if let Some(basename) = segments.last() {
        params.insert("path.basename".to_owned(), (*basename).to_owned());
        params.insert(
            "path.basenameNormalized".to_owned(),
            sanitize_dns1123(basename),
        );
    }
    params
}

/// One directory entry discovered by the bounded walk.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WalkEntry {
    path: String,
    is_dir: bool,
}

/// Walks `root` once, iteratively, skipping hidden and symlinked entries.
///
/// Symlinks are never followed: a hostile repository must not be able to make the generator read
/// `/etc/passwd` through a link (the `RepoCache` also runs `sanitize_worktree` over the whole tree
/// before publishing it; this is the second, read-time check).
///
/// A read/stat failure is reported as **retryable**: the worktree is a cached artifact, and the next
/// pass materializes it again (a torn checkout, a full disk, or a directory removed mid-walk is
/// transient), while [`ApplicationSetError::WalkBudgetExceeded`] stays terminal — the same
/// repository will not shrink.
fn walk_worktree(root: &Path) -> Result<Vec<WalkEntry>, ApplicationSetError> {
    let mut entries = Vec::new();
    let mut pending: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];
    let mut visited = 0_usize;
    while let Some((directory, prefix)) = pending.pop() {
        let read = std::fs::read_dir(&directory).map_err(|err| {
            ApplicationSetError::generator(
                "git",
                format!("could not read a worktree directory: {err}"),
                true,
            )
        })?;
        let mut children: Vec<(String, PathBuf, bool)> = Vec::new();
        for entry in read {
            let entry = entry.map_err(|err| {
                ApplicationSetError::generator(
                    "git",
                    format!("could not read a worktree entry: {err}"),
                    true,
                )
            })?;
            visited += 1;
            if visited > MAX_GIT_WALK_ENTRIES {
                return Err(ApplicationSetError::WalkBudgetExceeded {
                    limit: MAX_GIT_WALK_ENTRIES,
                });
            }
            let file_type = entry.file_type().map_err(|err| {
                ApplicationSetError::generator(
                    "git",
                    format!("could not stat a worktree entry: {err}"),
                    true,
                )
            })?;
            // Symlinks are neither followed nor reported.
            if file_type.is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            // `.git` and every other hidden entry are implementation detail, never parameters.
            if name.starts_with('.') {
                continue;
            }
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            let is_dir = file_type.is_dir();
            entries.push(WalkEntry {
                path: relative.clone(),
                is_dir,
            });
            if is_dir {
                children.push((relative, entry.path(), true));
            }
        }
        // Deterministic traversal regardless of `readdir` order.
        children.sort_by(|left, right| right.0.cmp(&left.0));
        for (relative, absolute_path, _) in children {
            pending.push((absolute_path, relative));
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

/// Reads one parameter file under a size and symlink guard.
fn read_parameter_file(absolute: &Path, relative: &str) -> Result<String, ApplicationSetError> {
    let metadata =
        std::fs::symlink_metadata(absolute).map_err(|err| ApplicationSetError::ParameterFile {
            path: relative.to_owned(),
            message: format!("could not stat the file: {err}"),
        })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApplicationSetError::ParameterFile {
            path: relative.to_owned(),
            message: "not a regular file (symlinks are never followed)".to_owned(),
        });
    }
    if metadata.len() > MAX_PARAMETER_FILE_BYTES {
        return Err(ApplicationSetError::ParameterFile {
            path: relative.to_owned(),
            message: format!(
                "larger than the {MAX_PARAMETER_FILE_BYTES} byte parameter-file budget"
            ),
        });
    }
    std::fs::read_to_string(absolute).map_err(|err| ApplicationSetError::ParameterFile {
        path: relative.to_owned(),
        message: format!("could not read the file as UTF-8: {err}"),
    })
}

/// Turns one parsed parameter document into parameter sets.
///
/// A mapping is one parameter set (top-level scalars only); a sequence of mappings is one set per
/// element. Everything else is refused: nested values would need a templating language to address,
/// which this feature deliberately does not have.
fn params_from_document(
    document: &Value,
    path: &str,
) -> Result<Vec<ParamMap>, ApplicationSetError> {
    match document {
        Value::Object(_) => Ok(vec![object_params(document, path, None)?]),
        Value::Array(items) => {
            let mut params = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                if !item.is_object() {
                    return Err(ApplicationSetError::ParameterFile {
                        path: path.to_owned(),
                        message: format!(
                            "element {index} of the sequence is not a mapping of parameters"
                        ),
                    });
                }
                params.push(object_params(item, path, Some(index))?);
            }
            Ok(params)
        }
        _ => Err(ApplicationSetError::ParameterFile {
            path: path.to_owned(),
            message: "the document must be a mapping or a sequence of mappings".to_owned(),
        }),
    }
}

fn object_params(
    document: &Value,
    path: &str,
    index: Option<usize>,
) -> Result<ParamMap, ApplicationSetError> {
    let Some(object) = document.as_object() else {
        return Err(ApplicationSetError::ParameterFile {
            path: path.to_owned(),
            message: "the parameter document must be a mapping".to_owned(),
        });
    };
    let mut params = path_params(path);
    if let Some(index) = index {
        params.insert("index".to_owned(), index.to_string());
    }
    for (key, value) in object {
        if !is_valid_parameter_key(key) {
            return Err(ApplicationSetError::ParameterFile {
                path: path.to_owned(),
                message: format!(
                    "the key {key:?} is not a flat placeholder name (allowed: [A-Za-z0-9_.-])"
                ),
            });
        }
        let scalar = match value {
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(boolean) => boolean.to_string(),
            Value::Null => String::new(),
            Value::Array(_) | Value::Object(_) => {
                return Err(ApplicationSetError::ParameterFile {
                    path: path.to_owned(),
                    message: format!(
                        "the value of {key:?} is not a scalar; parameter values must be strings, \
                         numbers, booleans, or null"
                    ),
                });
            }
        };
        params.insert(key.clone(), scalar);
    }
    Ok(params)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ferriscd_crd::applicationset::ClusterSelector;

    use super::*;

    struct FakeClusters(Vec<ClusterRegistration>);

    impl ClusterParamSource for FakeClusters {
        fn clusters(&self) -> Vec<ClusterRegistration> {
            self.0.clone()
        }
    }

    struct FakeGit {
        root: PathBuf,
    }

    impl GitParameterSource for FakeGit {
        fn checkout<'a>(
            &'a self,
            _repo_url: &'a str,
            _revision: &'a str,
        ) -> RepoFuture<'a, RepoCheckout> {
            Box::pin(async move {
                Ok(RepoCheckout::new(
                    self.root.clone(),
                    "0123456789abcdef0123456789abcdef01234567",
                ))
            })
        }
    }

    struct NoClusters;
    impl ClusterParamSource for NoClusters {
        fn clusters(&self) -> Vec<ClusterRegistration> {
            Vec::new()
        }
    }

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn git_generator(
        directories: Vec<GitDirectoryPattern>,
        files: Vec<GitFilePattern>,
    ) -> GitGenerator {
        GitGenerator {
            repo_url: "https://github.com/example/config.git".to_owned(),
            revision: "HEAD".to_owned(),
            directories,
            files,
        }
    }

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write fixture file");
    }

    #[test]
    fn list_parameters_keep_the_declared_order_and_are_capped() {
        let list = ListGenerator {
            elements: vec![
                labels(&[("env", "dev"), ("size", "1")]),
                labels(&[("env", "prod"), ("size", "3")]),
            ],
        };
        let params = expand_list(10, &list).expect("two elements fit");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].get("env").map(String::as_str), Some("dev"));
        assert_eq!(params[1].get("size").map(String::as_str), Some("3"));

        let error = expand_list(1, &list).expect_err("the cap must refuse, never truncate");
        assert!(matches!(
            error,
            ApplicationSetError::FanOutLimitExceeded {
                requested: 2,
                limit: 1,
                ..
            }
        ));
    }

    #[test]
    fn cluster_parameters_are_sorted_selected_and_credential_free() {
        let registrations = vec![
            ClusterRegistration::new("eu-prod", labels(&[("env", "prod"), ("region", "eu")]))
                .with_default_namespace("payments"),
            ClusterRegistration::new("us-dev", labels(&[("env", "dev"), ("region", "us")])),
            ClusterRegistration::new("us-prod", labels(&[("env", "prod"), ("region", "us")])),
            // A duplicate name must not duplicate the generated Application: the first wins.
            ClusterRegistration::new("us-prod", labels(&[("env", "dev")])),
        ];
        let all = build_cluster_params(registrations.clone(), &ClusterGenerator::default());
        let names: Vec<&str> = all
            .iter()
            .filter_map(|params| params.get("name").map(String::as_str))
            .collect();
        assert_eq!(names, vec!["eu-prod", "us-dev", "us-prod"]);

        let selector = ClusterGenerator {
            selector: Some(ClusterSelector {
                match_labels: labels(&[("env", "prod"), ("region", "eu")]),
            }),
        };
        let selected = build_cluster_params(registrations, &selector);
        assert_eq!(selected.len(), 1);
        let params = &selected[0];
        assert_eq!(params.get("name").map(String::as_str), Some("eu-prod"));
        assert_eq!(
            params.get("cluster.name").map(String::as_str),
            Some("eu-prod")
        );
        assert_eq!(
            params.get("cluster.defaultNamespace").map(String::as_str),
            Some("payments")
        );
        assert_eq!(
            params.get("metadata.labels.env").map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            params.get("metadata.labels.region").map(String::as_str),
            Some("eu")
        );
    }

    #[test]
    fn cluster_selector_requires_every_label() {
        let registration = ClusterRegistration::new("eu-prod", labels(&[("env", "prod")]));
        let selector = ClusterGenerator {
            selector: Some(ClusterSelector {
                match_labels: labels(&[("env", "prod"), ("tier", "gold")]),
            }),
        };
        assert!(
            build_cluster_params(vec![registration], &selector).is_empty(),
            "a selector must match all matchLabels, not any"
        );
    }

    #[tokio::test]
    async fn the_cluster_generator_uses_the_injected_source_and_caps_the_result() {
        let source = FakeClusters(vec![
            ClusterRegistration::new("b", BTreeMap::new()),
            ClusterRegistration::new("a", BTreeMap::new()),
            ClusterRegistration::new("c", BTreeMap::new()),
        ]);
        let git = FakeGit {
            root: PathBuf::from("/nonexistent"),
        };
        let context = GeneratorContext::new(&source, &git, 2);
        let generator = ApplicationSetGenerator::Clusters(ClusterGenerator::default());
        let error = expand(&context, &generator)
            .await
            .expect_err("three clusters exceed a cap of two");
        assert!(matches!(
            error,
            ApplicationSetError::FanOutLimitExceeded {
                requested: 3,
                limit: 2,
                ..
            }
        ));

        let context = GeneratorContext::new(&source, &git, 3);
        let params = expand(&context, &generator).await.expect("fits");
        let names: Vec<&str> = params
            .iter()
            .filter_map(|params| params.get("name").map(String::as_str))
            .collect();
        assert_eq!(
            names,
            vec!["a", "b", "c"],
            "the source order is sorted, not trusted"
        );
    }

    #[test]
    fn glob_matching_is_segment_aware() {
        assert!(glob_matches("apps/*", "apps/api"));
        assert!(!glob_matches("apps/*", "apps/api/v1"));
        assert!(glob_matches("apps/**", "apps/api/v1"));
        assert!(glob_matches("apps/**", "apps"));
        assert!(glob_matches("**/prod.yaml", "envs/prod.yaml"));
        assert!(glob_matches("**/prod.yaml", "envs/eu/prod.yaml"));
        assert!(glob_matches("envs/*/config.yaml", "envs/eu/config.yaml"));
        assert!(!glob_matches("envs/*/config.yaml", "envs/eu/other.yaml"));
        assert!(glob_matches("envs/*.yaml", "envs/eu.yaml"));
        assert!(glob_matches("apps/?pi", "apps/api"));
        assert!(!glob_matches("apps/?pi", "apps/apii"));
        assert!(glob_matches("*", "single"));
        assert!(!glob_matches("*", "two/segments"));
        // `**` in the middle, and several of them, still behave like "any number of segments".
        assert!(glob_matches(
            "**/envs/**/config.yaml",
            "a/b/envs/x/y/config.yaml"
        ));
        assert!(glob_matches("**/**/config.yaml", "config.yaml"));
        assert!(!glob_matches("**/**/config.yaml", "envs/config.yaml.bak"));
        assert!(glob_matches("", ""));
    }

    /// **Finding M4:** a `**` chain must not be exponential. The old recursive matcher re-derived
    /// every suffix, so `**/**/…/**` against a segmented path cost `O(segments^k)` and could pin a
    /// reconcile thread. The table matcher is `O(pattern × path)`, and a pair that would exceed
    /// [`MAX_GLOB_CELLS`] is refused outright instead of being attempted.
    #[test]
    fn pathological_glob_chains_complete_or_are_refused_instead_of_pinning_the_loop() {
        // 32 `**` segments against a 40-segment path is 32^40 recursive branches — this assertion
        // only terminates because matching is now a table walk.
        let path = (0..40)
            .map(|index| format!("seg{index}"))
            .collect::<Vec<_>>()
            .join("/");
        let needle = format!("{path}/leaf");
        let deep = format!("{}/leaf", vec!["**"; 32].join("/"));
        assert!(glob_matches(&deep, &needle));
        assert!(!glob_matches(&deep, &format!("{path}/other")));

        // A pattern so long that the segment table would exceed the budget is refused as a
        // non-match rather than evaluated.
        let huge_pattern = vec!["**"; MAX_GLOB_CELLS + 1].join("/");
        let huge_path = (0..4)
            .map(|index| format!("seg{index}"))
            .collect::<Vec<_>>()
            .join("/");
        assert!(
            !glob_matches(&huge_pattern, &huge_path),
            "an over-budget pattern must refuse, not run"
        );
        // The budget is a product, so a long path with a short pattern is also refused.
        let long_path = vec!["seg"; MAX_GLOB_CELLS].join("/");
        assert!(!glob_matches("**", &long_path));
        // …while the ordinary shapes stay cheap and correct.
        assert!(glob_matches("**", "seg/seg/seg"));
    }

    #[tokio::test]
    async fn git_directory_globs_are_sorted_filtered_and_bounded() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        write(directory.path(), "apps/api/main.go", "package main");
        write(directory.path(), "apps/web/index.html", "<html>");
        write(directory.path(), "apps/legacy/old.go", "package old");
        write(directory.path(), "charts/api/Chart.yaml", "name: api");
        write(directory.path(), ".git/config", "[core]");
        write(
            directory.path(),
            "envs/dev/config.yaml",
            "cluster: dev\nreplicas: 1\nenabled: true\n",
        );

        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };
        let context = GeneratorContext::new(&NoClusters, &git, 10);
        let generator = ApplicationSetGenerator::Git(git_generator(
            vec![
                GitDirectoryPattern {
                    path: "apps/**".to_owned(),
                    exclude: false,
                },
                GitDirectoryPattern {
                    path: "apps/legacy".to_owned(),
                    exclude: true,
                },
            ],
            Vec::new(),
        ));
        let params = expand(&context, &generator).await.expect("must expand");
        let paths: Vec<&str> = params
            .iter()
            .filter_map(|params| params.get("path").map(String::as_str))
            .collect();
        assert_eq!(
            paths,
            vec!["apps", "apps/api", "apps/web"],
            "sorted, `.git` skipped, and the excluded directory removed"
        );
        let api = &params[1];
        assert_eq!(api.get("path.basename").map(String::as_str), Some("api"));
        assert_eq!(api.get("path[0]").map(String::as_str), Some("apps"));
        assert_eq!(api.get("path[1]").map(String::as_str), Some("api"));
        assert_eq!(
            api.get("path.basenameNormalized").map(String::as_str),
            Some("api")
        );

        // The cap applies to a *successful* expansion, so nothing is silently truncated.
        let context = GeneratorContext::new(&NoClusters, &git, 2);
        let error = expand(&context, &generator)
            .await
            .expect_err("three directories exceed a cap of two");
        assert!(matches!(
            error,
            ApplicationSetError::FanOutLimitExceeded { requested: 3, .. }
        ));
    }

    #[tokio::test]
    async fn git_parameter_files_yield_path_and_document_parameters() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        write(
            directory.path(),
            "envs/dev/config.yaml",
            "cluster: dev\nreplicas: 1\nflag: true\n",
        );
        write(
            directory.path(),
            "envs/prod/config.json",
            r#"{"cluster":"prod","replicas":3}"#,
        );
        write(
            directory.path(),
            "envs/multi/config.yaml",
            "- cluster: one\n- cluster: two\n",
        );
        write(directory.path(), "envs/README.md", "not a parameter file");

        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };
        let context = GeneratorContext::new(&NoClusters, &git, 10);
        let generator = ApplicationSetGenerator::Git(git_generator(
            Vec::new(),
            vec![GitFilePattern {
                path: "envs/**/config.*".to_owned(),
                exclude: false,
            }],
        ));
        let params = expand(&context, &generator).await.expect("must expand");
        let paths: Vec<&str> = params
            .iter()
            .filter_map(|params| params.get("path").map(String::as_str))
            .collect();
        assert_eq!(
            paths,
            vec![
                "envs/dev/config.yaml",
                "envs/multi/config.yaml",
                "envs/multi/config.yaml",
                "envs/prod/config.json"
            ],
            "one parameter set per document, in sorted path order"
        );
        assert_eq!(params[0].get("cluster").map(String::as_str), Some("dev"));
        assert_eq!(params[0].get("replicas").map(String::as_str), Some("1"));
        assert_eq!(params[0].get("flag").map(String::as_str), Some("true"));
        assert_eq!(
            params[0].get("path.basename").map(String::as_str),
            Some("config.yaml")
        );

        let multi_one = &params[1];
        let multi_two = &params[2];
        assert_eq!(multi_one.get("cluster").map(String::as_str), Some("one"));
        assert_eq!(multi_one.get("index").map(String::as_str), Some("0"));
        assert_eq!(multi_two.get("cluster").map(String::as_str), Some("two"));
        assert_eq!(multi_two.get("index").map(String::as_str), Some("1"));

        assert_eq!(params[3].get("cluster").map(String::as_str), Some("prod"));
        assert_eq!(params[3].get("replicas").map(String::as_str), Some("3"));
    }

    #[tokio::test]
    async fn unsafe_or_unusable_parameter_documents_are_refused() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        write(
            directory.path(),
            "envs/nested.yaml",
            "labels:\n  team: payments\n",
        );
        write(directory.path(), "envs/scalar.yaml", "just-a-string\n");
        write(directory.path(), "envs/bad.yaml", "a: [unclosed\n");
        write(directory.path(), "envs/duplicate.yaml", "a: 1\na: 2\n");
        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };

        for (pattern, expected) in [
            ("envs/nested.yaml", "not a scalar"),
            ("envs/scalar.yaml", "mapping or a sequence"),
            ("envs/duplicate.yaml", "parser budgets"),
        ] {
            let context = GeneratorContext::new(&NoClusters, &git, 10);
            let generator = ApplicationSetGenerator::Git(git_generator(
                Vec::new(),
                vec![GitFilePattern {
                    path: pattern.to_owned(),
                    exclude: false,
                }],
            ));
            let error = expand(&context, &generator)
                .await
                .expect_err("the document must be refused");
            assert!(
                error.to_string().contains(expected),
                "{pattern}: expected {expected:?}, got {error}"
            );
            assert!(matches!(error, ApplicationSetError::ParameterFile { .. }));
        }
    }

    #[tokio::test]
    async fn a_parameter_file_over_the_size_budget_is_refused() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        // One byte over `MAX_PARAMETER_FILE_BYTES`: a hostile or accidentally committed blob must be
        // refused from its metadata, never parsed into the engine's heap.
        let budget = usize::try_from(MAX_PARAMETER_FILE_BYTES).expect("the budget fits in usize");
        let oversized = format!("a: {}", "x".repeat(budget));
        assert!(oversized.len() > budget);
        write(directory.path(), "envs/huge.yaml", &oversized);

        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };
        let context = GeneratorContext::new(&NoClusters, &git, 10);
        let generator = ApplicationSetGenerator::Git(git_generator(
            Vec::new(),
            vec![GitFilePattern {
                path: "envs/huge.yaml".to_owned(),
                exclude: false,
            }],
        ));
        let error = expand(&context, &generator)
            .await
            .expect_err("the parameter-file size budget must refuse the file");
        assert!(
            error.to_string().contains("budget"),
            "the refusal must name the budget: {error}"
        );
        assert!(matches!(error, ApplicationSetError::ParameterFile { .. }));
    }

    #[tokio::test]
    async fn a_worktree_over_the_walk_budget_is_refused() {
        // A repository that ships an unbounded tree must not turn one reconcile into an unbounded
        // disk scan: the walk stops at `MAX_GIT_WALK_ENTRIES` and reports a terminal error rather
        // than returning a silently truncated parameter list.
        let directory = tempfile::TempDir::new().expect("temp dir");
        let crowded = directory.path().join("apps");
        fs::create_dir_all(&crowded).expect("create the crowded directory");
        for index in 0..=MAX_GIT_WALK_ENTRIES {
            fs::write(crowded.join(format!("e{index}")), "").expect("write a walk entry");
        }

        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };
        let context = GeneratorContext::new(&NoClusters, &git, MAX_GENERATED_APPS);
        let generator = ApplicationSetGenerator::Git(git_generator(
            vec![GitDirectoryPattern {
                path: "apps".to_owned(),
                exclude: false,
            }],
            Vec::new(),
        ));
        let error = expand(&context, &generator)
            .await
            .expect_err("the walk budget must refuse the tree");
        assert!(
            error
                .to_string()
                .contains(&MAX_GIT_WALK_ENTRIES.to_string()),
            "the refusal must name the walk budget: {error}"
        );
        assert!(
            !error.is_retryable(),
            "a huge tree will not shrink by retrying"
        );
    }

    #[tokio::test]
    async fn parameter_file_errors_never_quote_the_file_contents() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        // A parameter file is untrusted: whatever it holds may be a credential, so an error about
        // it may name the path and the offending *key*, never a value.
        write(
            directory.path(),
            "envs/awful.yaml",
            "password: \"s3cr3t-value\"\nbad{key}: 1\n",
        );
        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };
        let context = GeneratorContext::new(&NoClusters, &git, 10);
        let generator = ApplicationSetGenerator::Git(git_generator(
            Vec::new(),
            vec![GitFilePattern {
                path: "envs/awful.yaml".to_owned(),
                exclude: false,
            }],
        ));
        let error = expand(&context, &generator)
            .await
            .expect_err("the unusable key is refused");
        let rendered = format!("{error}\n{error:?}");
        assert!(
            !rendered.contains("s3cr3t-value"),
            "a parameter *value* must never reach an error: {rendered}"
        );
        assert!(
            rendered.contains("envs/awful.yaml"),
            "the error names the file: {rendered}"
        );
        assert!(
            rendered.contains("bad{key}"),
            "the error names the offending key: {rendered}"
        );
    }

    #[tokio::test]
    async fn symlinks_are_never_followed() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        let outside = tempfile::TempDir::new().expect("outside dir");
        fs::write(outside.path().join("secret.yaml"), "cluster: stolen\n").expect("write");
        write(directory.path(), "envs/real.yaml", "cluster: real\n");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                outside.path().join("secret.yaml"),
                directory.path().join("envs/link.yaml"),
            )
            .expect("create symlink");
            std::os::unix::fs::symlink(outside.path(), directory.path().join("envs/linked-dir"))
                .expect("create directory symlink");
        }
        #[cfg(not(unix))]
        {
            // The platform cannot create the fixture; the guard itself is still exercised below.
        }

        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };
        let context = GeneratorContext::new(&NoClusters, &git, 10);
        let generator = ApplicationSetGenerator::Git(git_generator(
            Vec::new(),
            vec![GitFilePattern {
                path: "envs/*".to_owned(),
                exclude: false,
            }],
        ));
        let params = expand(&context, &generator).await.expect("must expand");
        // Only the regular file is discovered; `link.yaml` and `linked-dir` are invisible.
        assert_eq!(params.len(), 1);
        assert_eq!(
            params[0].get("path").map(String::as_str),
            Some("envs/real.yaml")
        );
        assert_eq!(params[0].get("cluster").map(String::as_str), Some("real"));
    }

    #[tokio::test]
    async fn matrix_expansion_is_a_deterministic_product_with_right_hand_precedence() {
        let source = FakeClusters(vec![
            ClusterRegistration::new("prod", BTreeMap::new()),
            ClusterRegistration::new("dev", BTreeMap::new()),
        ]);
        let git = FakeGit {
            root: PathBuf::from("/nonexistent"),
        };
        let context = GeneratorContext::new(&source, &git, 10);
        let generator = ApplicationSetGenerator::Matrix(MatrixGenerator {
            generators: vec![
                MatrixChildGenerator::Clusters(ClusterGenerator::default()),
                MatrixChildGenerator::List(ListGenerator {
                    elements: vec![
                        labels(&[("path", "apps/api"), ("env", "one")]),
                        labels(&[("path", "apps/web"), ("env", "two")]),
                    ],
                }),
            ],
        });
        let params = expand(&context, &generator).await.expect("must expand");
        assert_eq!(params.len(), 4);
        let pairs: Vec<(String, String)> = params
            .iter()
            .map(|params| {
                (
                    params.get("name").cloned().unwrap_or_default(),
                    params.get("path").cloned().unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("dev".to_owned(), "apps/api".to_owned()),
                ("dev".to_owned(), "apps/web".to_owned()),
                ("prod".to_owned(), "apps/api".to_owned()),
                ("prod".to_owned(), "apps/web".to_owned()),
            ],
            "left-major, right-minor, both sides sorted"
        );

        // A key produced by both sides resolves deterministically to the right-hand value.
        let generator = ApplicationSetGenerator::Matrix(MatrixGenerator {
            generators: vec![
                MatrixChildGenerator::List(ListGenerator {
                    elements: vec![labels(&[("k", "left")])],
                }),
                MatrixChildGenerator::List(ListGenerator {
                    elements: vec![labels(&[("k", "right")])],
                }),
            ],
        });
        let params = expand(&context, &generator).await.expect("must expand");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].get("k").map(String::as_str), Some("right"));
    }

    #[tokio::test]
    async fn a_fan_out_bomb_is_refused_before_it_is_materialized() {
        let source = FakeClusters(
            (0..20)
                .map(|index| {
                    ClusterRegistration::new(format!("cluster-{index:02}"), BTreeMap::new())
                })
                .collect(),
        );
        let git = FakeGit {
            root: PathBuf::from("/nonexistent"),
        };
        let context = GeneratorContext::new(&source, &git, MAX_GENERATED_APPS);
        let generator = ApplicationSetGenerator::Matrix(MatrixGenerator {
            generators: vec![
                MatrixChildGenerator::Clusters(ClusterGenerator::default()),
                // 20 x 11 = 220 > 200.
                MatrixChildGenerator::List(ListGenerator {
                    elements: (0..11).map(|_| ParamMap::new()).collect(),
                }),
            ],
        });
        let error = expand(&context, &generator)
            .await
            .expect_err("220 Applications exceed the hard cap");
        assert!(matches!(
            error,
            ApplicationSetError::FanOutLimitExceeded {
                requested: 220,
                limit: MAX_GENERATED_APPS,
                ..
            }
        ));
        assert!(!error.is_retryable(), "the generators have to change");
    }

    #[tokio::test]
    async fn a_git_failure_is_retryable_and_content_free() {
        struct FailingGit;

        impl GitParameterSource for FailingGit {
            fn checkout<'a>(
                &'a self,
                _repo_url: &'a str,
                _revision: &'a str,
            ) -> RepoFuture<'a, RepoCheckout> {
                Box::pin(async {
                    Err(crate::repo::RepoError::Network {
                        message: "connection reset".to_owned(),
                    })
                })
            }
        }

        let git = FailingGit;
        let context = GeneratorContext::new(&NoClusters, &git, 10);
        let generator = ApplicationSetGenerator::Git(git_generator(
            vec![GitDirectoryPattern {
                path: "apps/*".to_owned(),
                exclude: false,
            }],
            Vec::new(),
        ));
        let error = expand(&context, &generator)
            .await
            .expect_err("the checkout failed");
        assert!(
            error.is_retryable(),
            "a transient Git error must be retried"
        );
        assert!(error.to_string().contains("git generator"), "{error}");
    }

    /// **Finding H2:** the retry classification of the repository error underneath a generator
    /// failure is *carried*, never guessed. `RevisionNotFound`, `AuthFailed`, and `UnsafeSymlink` are
    /// verdicts about the repository or the credentials — another pass with the same inputs changes
    /// nothing — while a dropped connection is exactly what the retry is for.
    #[tokio::test]
    async fn generator_failures_carry_the_repository_retry_classification() {
        /// Builds the scripted repository error for one table row.
        type RepoErrorFactory = fn() -> crate::repo::RepoError;

        /// A checkout that always fails with the same scripted repository error.
        struct FailingGit(RepoErrorFactory);

        impl GitParameterSource for FailingGit {
            fn checkout<'a>(
                &'a self,
                _repo_url: &'a str,
                _revision: &'a str,
            ) -> RepoFuture<'a, RepoCheckout> {
                let error = (self.0)();
                Box::pin(async move { Err(error) })
            }
        }

        let generator = ApplicationSetGenerator::Git(git_generator(
            vec![GitDirectoryPattern {
                path: "apps/*".to_owned(),
                exclude: false,
            }],
            Vec::new(),
        ));
        let cases: [(&str, RepoErrorFactory, bool); 4] = [
            (
                "RevisionNotFound",
                || crate::repo::RepoError::RevisionNotFound {
                    revision: "v9.9.9".to_owned(),
                },
                false,
            ),
            (
                "AuthFailed",
                || crate::repo::RepoError::AuthFailed {
                    reason: "invalid token".to_owned(),
                },
                false,
            ),
            (
                "UnsafeSymlink",
                || crate::repo::RepoError::UnsafeSymlink {
                    path: PathBuf::from("apps/link"),
                    target: PathBuf::from("/etc/passwd"),
                    reason: "escapes the checkout root".to_owned(),
                },
                false,
            ),
            (
                "Network",
                || crate::repo::RepoError::Network {
                    message: "connection reset".to_owned(),
                },
                true,
            ),
        ];
        for (label, repo_error, expected) in cases {
            assert_eq!(
                repo_error().is_retryable(),
                expected,
                "{label}: the fixture must match `RepoError::is_retryable`"
            );
            let git = FailingGit(repo_error);
            let context = GeneratorContext::new(&NoClusters, &git, 10);
            let error = expand(&context, &generator)
                .await
                .expect_err("the checkout failed");
            assert_eq!(
                error.reason(),
                "GeneratorError",
                "{label}: every Git failure is a generator failure"
            );
            assert_eq!(
                error.is_retryable(),
                expected,
                "{label}: the engine must report the repository's own classification, got {error:?}"
            );
        }

        // A matrix arity mistake is a spec problem, never a transient one.
        let matrix = ApplicationSetGenerator::Matrix(MatrixGenerator {
            generators: vec![MatrixChildGenerator::Clusters(ClusterGenerator::default())],
        });
        let git = FakeGit {
            root: PathBuf::from("/nonexistent"),
        };
        let context = GeneratorContext::new(&NoClusters, &git, 10);
        let error = expand(&context, &matrix)
            .await
            .expect_err("a one-child matrix is refused");
        assert!(!error.is_retryable(), "matrix arity cannot be retried");
    }

    /// The fan-out cap is enforced *inside* the parameter-file branch: one file may hold a sequence,
    /// so "how many files matched" is not the number of generated `Application`s.
    #[tokio::test]
    async fn the_parameter_file_branch_enforces_the_cap_while_reading() {
        let directory = tempfile::TempDir::new().expect("temp dir");
        // Two matched files, each a sequence of three parameter sets: six sets from two files, over a
        // cap of four. The refusal must not depend on the file *count*.
        for name in ["envs/a.yaml", "envs/b.yaml"] {
            write(
                directory.path(),
                name,
                "- cluster: one\n- cluster: two\n- cluster: three\n",
            );
        }
        let git = FakeGit {
            root: directory.path().to_path_buf(),
        };
        let context = GeneratorContext::new(&NoClusters, &git, 4);
        let generator = ApplicationSetGenerator::Git(git_generator(
            Vec::new(),
            vec![GitFilePattern {
                path: "envs/*.yaml".to_owned(),
                exclude: false,
            }],
        ));
        let error = expand(&context, &generator)
            .await
            .expect_err("six parameter sets exceed a cap of four");
        assert!(
            matches!(
                error,
                ApplicationSetError::FanOutLimitExceeded {
                    requested: 6,
                    limit: 4,
                    ..
                }
            ),
            "expected a fan-out refusal at the cap, got {error:?}"
        );
        assert!(!error.is_retryable());

        // Exactly at the cap is allowed, so the guard is a ceiling and not an off-by-one.
        let context = GeneratorContext::new(&NoClusters, &git, 6);
        let params = expand(&context, &generator).await.expect("six sets fit");
        assert_eq!(params.len(), 6);
    }
}
