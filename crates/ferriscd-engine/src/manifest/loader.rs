//! Safe, deterministic manifest directory/file walker.
//!
//! The walker is a second line of defense alongside the worktree-wide symlink
//! sanitizer (`repo::sanitize`): it canonicalizes `checkout.root_dir.join(path)`
//! and refuses anything that resolves outside the checkout root. Directory
//! discovery is deterministic (sorted by repository-relative path), skips hidden
//! dot-directories and non-manifest files, and enforces file-count and total-byte
//! budgets.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use super::error::ManifestError;

/// Default maximum number of manifest files loaded from one source path.
pub const DEFAULT_MAX_FILES: usize = 10_000;

/// Default maximum total bytes of manifest content loaded from one source path.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 128 * 1024 * 1024;

/// Manifests recognised by the loader.
const MANIFEST_EXTENSIONS: [&str; 3] = [".yaml", ".yml", ".json"];

/// Bounds enforced while collecting manifest files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLoaderConfig {
    /// Maximum number of manifest files.
    pub max_files: usize,
    /// Maximum cumulative byte size of manifest content.
    pub max_total_bytes: u64,
    /// Descend into sub-directories of `source_path` (default `true`).
    ///
    /// `spec.source.renderer.plainYaml.recursive: false` maps to `false`, which loads only the
    /// manifest files directly inside `source_path` (or the single file it names).
    pub recursive: bool,
}

impl Default for ManifestLoaderConfig {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            recursive: true,
        }
    }
}

impl ManifestLoaderConfig {
    /// Creates a loader configuration with default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of manifest files.
    #[must_use]
    pub fn with_max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    /// Sets the maximum cumulative byte size.
    #[must_use]
    pub fn with_max_total_bytes(mut self, max_total_bytes: u64) -> Self {
        self.max_total_bytes = max_total_bytes;
        self
    }

    /// Sets whether sub-directories of the source path are walked.
    #[must_use]
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }
}

/// A loaded manifest file with its repository-relative source path and contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFile {
    /// Repository-relative source path (e.g. `apps/base/deployment.yaml`).
    pub source_file: String,
    /// Raw file contents.
    pub contents: String,
}

/// Loads all manifest files under `root.join(source_path)`.
///
/// `source_path` may name a single manifest file or a directory. Discovered files
/// are sorted by repository-relative path so downstream ordering is deterministic.
///
/// # Errors
///
/// Returns [`ManifestError::NotFound`] for a missing path, [`ManifestError::PathEscape`]
/// when the path escapes `root`, [`ManifestError::LimitExceeded`] when a budget is
/// exceeded, and [`ManifestError::Io`] for filesystem failures.
pub fn load(
    root: &Path,
    source_path: &str,
    config: &ManifestLoaderConfig,
) -> Result<Vec<ManifestFile>, ManifestError> {
    let canonical_root = std::fs::canonicalize(root).map_err(|source| ManifestError::Io {
        context: format!("canonicalizing checkout root '{}'", root.display()),
        source,
    })?;

    let joined = canonical_root.join(source_path);

    // Lexical `..` containment check, performed before the existence check so an
    // escaping path is rejected even when the target does not exist.
    let lexical = lexically_normalize(&joined);
    if !lexical.starts_with(&canonical_root) {
        return Err(ManifestError::PathEscape {
            path: joined.display().to_string(),
            root: canonical_root.display().to_string(),
        });
    }

    let canonical_target = match std::fs::canonicalize(&joined) {
        Ok(path) => path,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(ManifestError::NotFound {
                path: joined.display().to_string(),
            });
        }
        Err(source) => {
            return Err(ManifestError::Io {
                context: format!("canonicalizing manifest path '{}'", joined.display()),
                source,
            });
        }
    };

    // Symlink (or bind-mount) escape check after resolving the real path.
    if !canonical_target.starts_with(&canonical_root) {
        return Err(ManifestError::PathEscape {
            path: canonical_target.display().to_string(),
            root: canonical_root.display().to_string(),
        });
    }

    let metadata =
        std::fs::symlink_metadata(&canonical_target).map_err(|source| ManifestError::Io {
            context: format!("inspecting manifest path '{}'", canonical_target.display()),
            source,
        })?;

    let mut files: Vec<(String, PathBuf)> = Vec::new();
    let mut visited: HashSet<PathBuf> = HashSet::new();
    if metadata.is_file() {
        if !has_manifest_extension(&canonical_target) {
            return Err(ManifestError::InvalidPath {
                path: canonical_target.display().to_string(),
                reason: "unsupported file extension (expected .yaml, .yml, or .json)".to_owned(),
            });
        }
        files.push((
            source_file_name(&canonical_target, &canonical_root),
            canonical_target,
        ));
    } else if metadata.is_dir() {
        visited.insert(canonical_target.clone());
        collect_manifest_files(
            &canonical_root,
            &canonical_target,
            &mut files,
            &mut visited,
            config.recursive,
        )?;
    } else {
        return Err(ManifestError::InvalidPath {
            path: canonical_target.display().to_string(),
            reason: "manifest path must be a regular file or directory".to_owned(),
        });
    }

    // Global deterministic ordering by repository-relative path, then deduplicate by
    // canonical target so a manifest reached both directly and via an intra-repo symlink
    // is loaded exactly once.
    files.sort_by(|a, b| a.0.cmp(&b.0));
    files.dedup_by(|a, b| a.1 == b.1);

    if files.len() > config.max_files {
        return Err(ManifestError::LimitExceeded {
            reason: format!(
                "{} manifest files exceed the configured maximum of {}",
                files.len(),
                config.max_files
            ),
        });
    }

    let mut total_bytes: u64 = 0;
    let mut loaded = Vec::with_capacity(files.len());
    for (source_file, path) in files {
        let len = std::fs::metadata(&path)
            .map_err(|source| ManifestError::Io {
                context: format!("reading manifest metadata '{}'", path.display()),
                source,
            })?
            .len();
        total_bytes = total_bytes.saturating_add(len);
        if total_bytes > config.max_total_bytes {
            return Err(ManifestError::LimitExceeded {
                reason: format!(
                    "manifest content exceeds the configured maximum of {} bytes",
                    config.max_total_bytes
                ),
            });
        }

        let contents = std::fs::read_to_string(&path).map_err(|source| ManifestError::Io {
            context: format!("reading manifest '{}'", path.display()),
            source,
        })?;
        loaded.push(ManifestFile {
            source_file,
            contents,
        });
    }

    Ok(loaded)
}

/// Recursively collects regular manifest files under `dir`, skipping hidden dot-dirs.
///
/// Intra-repo symlinks are followed (both file and directory targets) after verifying
/// their canonical target stays inside `root`. `visited` holds canonical directory paths
/// already entered so a symlink cycle cannot recurse forever. `recursive == false` stops at the
/// first level: sub-directories (including symlinked ones) are not descended into.
fn collect_manifest_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
    visited: &mut HashSet<PathBuf>,
    recursive: bool,
) -> Result<(), ManifestError> {
    let read_dir = std::fs::read_dir(dir).map_err(|source| ManifestError::Io {
        context: format!("reading manifest directory '{}'", dir.display()),
        source,
    })?;

    let mut entries: Vec<_> =
        read_dir
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| ManifestError::Io {
                context: format!("enumerating manifest directory '{}'", dir.display()),
                source,
            })?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| ManifestError::Io {
            context: format!("inspecting manifest entry '{}'", path.display()),
            source,
        })?;

        if file_type.is_symlink() {
            collect_symlink_entry(root, &path, out, visited, recursive)?;
        } else if file_type.is_dir() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.') {
                // Hidden dot-directories (.git, .kustomize, ...) are never traversed.
                continue;
            }
            if !recursive {
                continue;
            }
            let canonical = std::fs::canonicalize(&path).map_err(|source| ManifestError::Io {
                context: format!("canonicalizing manifest directory '{}'", path.display()),
                source,
            })?;
            if visited.insert(canonical.clone()) {
                collect_manifest_files(root, &canonical, out, visited, recursive)?;
            }
        } else if file_type.is_file() && has_manifest_extension(&path) {
            out.push((source_file_name(&path, root), path));
        }
        // Non-manifest regular files and other special files are not manifests and are
        // therefore ignored (never silently skipped *because* they are symlinks).
    }

    Ok(())
}

/// Resolves one symlink encountered during the walk and includes its in-root target.
///
/// Escaping targets are rejected with [`ManifestError::PathEscape`]; broken targets are a
/// clear [`ManifestError::Io`] rather than a silent skip.
fn collect_symlink_entry(
    root: &Path,
    link: &Path,
    out: &mut Vec<(String, PathBuf)>,
    visited: &mut HashSet<PathBuf>,
    recursive: bool,
) -> Result<(), ManifestError> {
    let canonical = match std::fs::canonicalize(link) {
        Ok(path) => path,
        Err(source) => {
            return Err(ManifestError::Io {
                context: format!("resolving manifest symlink '{}'", link.display()),
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

    let metadata = std::fs::metadata(&canonical).map_err(|source| ManifestError::Io {
        context: format!("inspecting symlink target '{}'", canonical.display()),
        source,
    })?;

    if metadata.is_file() {
        if has_manifest_extension(&canonical) {
            out.push((source_file_name(&canonical, root), canonical));
        }
    } else if metadata.is_dir() {
        if recursive && visited.insert(canonical.clone()) {
            collect_manifest_files(root, &canonical, out, visited, recursive)?;
        }
    } else {
        return Err(ManifestError::InvalidPath {
            path: canonical.display().to_string(),
            reason: "symlink target must be a regular file or directory".to_owned(),
        });
    }

    Ok(())
}

/// Returns the repository-relative, `/`-separated path of `path` under `root`.
fn source_file_name(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn has_manifest_extension(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let lower = name.to_ascii_lowercase();
    MANIFEST_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

/// Lexically resolves `.` and `..` components (never touching the filesystem) so a
/// `..` traversal can be detected even when the target path does not exist.
pub(crate) fn lexically_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                // Pop the previous normal component; a root/prefix is never popped.
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn write(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, contents).expect("write fixture file");
    }

    #[test]
    fn loads_directory_deterministically_sorted_by_relative_path() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "z-last.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: z\n",
        );
        write(
            temp.path(),
            "a-first.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n",
        );
        write(temp.path(), "README.md", "not a manifest\n");
        write(
            temp.path(),
            "sub/b.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n",
        );

        let files =
            load(temp.path(), ".", &ManifestLoaderConfig::default()).expect("load directory");

        let names: Vec<&str> = files.iter().map(|f| f.source_file.as_str()).collect();
        assert_eq!(names, vec!["a-first.yaml", "sub/b.yaml", "z-last.yaml"]);
    }

    #[test]
    fn supports_single_file_target() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "app.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n",
        );
        write(
            temp.path(),
            "other.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: o\n",
        );

        let files = load(temp.path(), "app.yaml", &ManifestLoaderConfig::default())
            .expect("load single file");

        assert_eq!(files.len(), 1);
        assert_eq!(files[0].source_file, "app.yaml");
    }

    #[test]
    fn missing_path_is_reported() {
        let temp = TempDir::new().expect("tempdir");
        let err = load(temp.path(), "nope", &ManifestLoaderConfig::default())
            .expect_err("missing path must fail");
        assert!(matches!(err, ManifestError::NotFound { .. }), "{err:?}");
    }

    #[test]
    fn parent_traversal_escape_is_rejected_even_when_missing() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("repo");
        fs::create_dir_all(&root).expect("create repo root");

        // The parent directory exists, so this path escapes the checkout root.
        let err = load(&root, "../../etc", &ManifestLoaderConfig::default())
            .expect_err("escape must fail");
        assert!(matches!(err, ManifestError::PathEscape { .. }), "{err:?}");
    }

    #[test]
    fn existing_escape_through_parent_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().join("repo");
        fs::create_dir_all(&root).expect("create repo root");
        write(
            temp.path(),
            "outside.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: out\n",
        );

        let err = load(&root, "../outside.yaml", &ManifestLoaderConfig::default())
            .expect_err("escape must fail");
        assert!(matches!(err, ManifestError::PathEscape { .. }), "{err:?}");
    }

    #[test]
    fn hidden_dirs_and_non_manifest_files_are_skipped() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "visible.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: v\n",
        );
        write(
            temp.path(),
            ".git/config.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: hidden\n",
        );
        write(
            temp.path(),
            ".hidden-dir/a.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: h\n",
        );
        write(temp.path(), "notes.txt", "not yaml\n");

        let files =
            load(temp.path(), ".", &ManifestLoaderConfig::default()).expect("load directory");
        let names: Vec<&str> = files.iter().map(|f| f.source_file.as_str()).collect();
        assert_eq!(names, vec!["visible.yaml"]);
    }

    #[test]
    fn non_recursive_load_only_returns_top_level_manifests() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "top.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: top\n",
        );
        write(
            temp.path(),
            "nested/deep.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: deep\n",
        );

        let config = ManifestLoaderConfig::default().with_recursive(false);
        let files = load(temp.path(), ".", &config).expect("non-recursive load");
        let names: Vec<&str> = files.iter().map(|f| f.source_file.as_str()).collect();
        assert_eq!(names, vec!["top.yaml"]);

        // The default stays recursive, so Phase 03 behaviour is unchanged.
        let files =
            load(temp.path(), ".", &ManifestLoaderConfig::default()).expect("recursive load");
        let names: Vec<&str> = files.iter().map(|f| f.source_file.as_str()).collect();
        assert_eq!(names, vec!["nested/deep.yaml", "top.yaml"]);
    }

    #[test]
    fn file_count_limit_is_enforced() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "a.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n",
        );
        write(
            temp.path(),
            "b.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n",
        );

        let config = ManifestLoaderConfig::default().with_max_files(1);
        let err = load(temp.path(), ".", &config).expect_err("file count limit");
        assert!(
            matches!(err, ManifestError::LimitExceeded { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn total_byte_limit_is_enforced() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "a.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n",
        );
        write(
            temp.path(),
            "b.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n",
        );

        let config = ManifestLoaderConfig::default().with_max_total_bytes(10);
        let err = load(temp.path(), ".", &config).expect_err("total byte limit");
        assert!(
            matches!(err, ManifestError::LimitExceeded { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn lexical_normalizer_resolves_dot_and_dotdot() {
        let base = Path::new("/repo/root");
        assert_eq!(
            lexically_normalize(&base.join("a/./b")),
            Path::new("/repo/root/a/b")
        );
        assert_eq!(
            lexically_normalize(&base.join("../outside")),
            Path::new("/repo/outside")
        );
        assert_eq!(
            lexically_normalize(&base.join("a/../../x")),
            Path::new("/repo/x")
        );
    }

    #[cfg(unix)]
    #[test]
    fn intra_repo_symlinked_manifest_is_loaded() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "shared/cm.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-link\n",
        );
        fs::create_dir_all(temp.path().join("apps")).expect("create apps dir");
        std::os::unix::fs::symlink("../shared/cm.yaml", temp.path().join("apps/link.yaml"))
            .expect("create manifest symlink");

        let files = load(temp.path(), "apps", &ManifestLoaderConfig::default())
            .expect("intra-repo symlink must be followed");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].source_file, "shared/cm.yaml");
    }

    #[cfg(unix)]
    #[test]
    fn intra_repo_symlinked_directory_is_walked() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "shared/nested/cm.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: from-dir-link\n",
        );
        fs::create_dir_all(temp.path().join("apps")).expect("create apps dir");
        std::os::unix::fs::symlink("../shared", temp.path().join("apps/shared"))
            .expect("create directory symlink");

        let files = load(temp.path(), "apps", &ManifestLoaderConfig::default())
            .expect("intra-repo directory symlink must be walked");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].source_file, "shared/nested/cm.yaml");
    }

    #[cfg(unix)]
    #[test]
    fn escaping_symlink_inside_walked_dir_is_rejected() {
        let base = TempDir::new().expect("tempdir");
        let root = base.path().join("repo");
        let outside = base.path().join("outside");
        fs::create_dir_all(&root).expect("create repo root");
        fs::create_dir_all(&outside).expect("create outside dir");
        fs::write(
            outside.join("secret.yaml"),
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: out\n",
        )
        .expect("write outside manifest");
        std::os::unix::fs::symlink("../outside/secret.yaml", root.join("evil.yaml"))
            .expect("create escaping symlink");

        let err = load(&root, ".", &ManifestLoaderConfig::default())
            .expect_err("escaping symlink must be rejected");
        assert!(matches!(err, ManifestError::PathEscape { .. }), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_back_to_an_ancestor_is_not_recurred_forever() {
        let temp = TempDir::new().expect("tempdir");
        write(
            temp.path(),
            "sub/cm.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: once\n",
        );
        std::os::unix::fs::symlink("..", temp.path().join("sub/loop"))
            .expect("create ancestor link");

        let files = load(temp.path(), ".", &ManifestLoaderConfig::default())
            .expect("ancestor symlink must not recurse forever");
        let names: Vec<&str> = files.iter().map(|f| f.source_file.as_str()).collect();
        assert_eq!(names, vec!["sub/cm.yaml"]);
    }
}
