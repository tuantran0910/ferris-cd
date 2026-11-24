//! Worktree-wide symlink sanitizer and resource-budget enforcement.
//!
//! A Git worktree is untrusted input: even when a path-scoped manifest loader checks the
//! files it reads, future renderers (`kustomize`, `helm`, or a plugin) run directly on the
//! checked-out directory. A symlink such as `values.yaml ->
//! /var/run/secrets/kubernetes.io/serviceaccount/token` would otherwise let a renderer
//! exfiltrate cluster credentials. This module walks the **entire** worktree immediately
//! after materialization and rejects any symlink whose canonical target escapes the
//! checkout root, plus enforces configurable file-count and byte budgets so a malicious
//! repository cannot act as a checkout-bomb.
//!
//! The walk is iterative (an explicit stack, never recursion), never follows symlinks, and
//! performs its blocking filesystem work in the caller's blocking context (the callers in
//! [`super::cache`] and [`super::gix_client`] both invoke it inside
//! [`tokio::task::spawn_blocking`]).

use std::path::{Path, PathBuf};

use super::error::RepoError;

/// Default maximum number of filesystem entries allowed in a single checkout.
pub const DEFAULT_MAX_FILES: usize = 100_000;

/// Default maximum total bytes of regular-file content allowed in a single checkout
/// (`512 MiB`).
pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Configurable resource budgets enforced by [`sanitize_worktree`].
///
/// Every filesystem entry (file, directory, or symlink) *beneath* the checkout root is
/// counted against `max_files`; the root directory itself is not an entry of the tree and is
/// therefore never counted. Only regular-file bytes are counted against `max_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorktreeLimits {
    /// Maximum number of filesystem entries permitted beneath the checkout root.
    ///
    /// The root directory itself does not count.
    pub max_files: usize,
    /// Maximum total bytes of regular-file content permitted in one checkout.
    pub max_bytes: u64,
}

impl Default for WorktreeLimits {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

impl WorktreeLimits {
    /// Creates default limits ([`DEFAULT_MAX_FILES`] files, [`DEFAULT_MAX_BYTES`] bytes).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of filesystem entries permitted in one checkout.
    #[must_use]
    pub fn with_max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files;
        self
    }

    /// Sets the maximum total bytes of regular-file content permitted in one checkout.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }
}

/// Sanitizes the entire worktree rooted at `root`, rejecting symlink escapes and enforcing
/// `limits`.
///
/// # Behavior
///
/// * `root` is canonicalized first; the sanitizer then compares every symlink's canonical
///   target against that canonical root using component-aware [`Path::starts_with`]. The
///   comparison is deliberately component-aware (never a string prefix), so a sibling such as
///   `worktree-evil/` is **not** considered inside root `worktree/`.
/// * Symlinks are resolved with [`std::fs::canonicalize`], so a chain of relative links
///   (`../../` escapes), an absolute target outside the root, a broken link, or a symlink
///   loop are all rejected with a terminal [`RepoError::UnsafeSymlink`].
/// * An absolute target that canonicalizes *inside* the root is accepted, exactly like an
///   equivalent relative target.
/// * A symlink whose canonical target is its own parent directory or an ancestor of it
///   (for example `link -> .` or `sub/link -> ..`) is rejected: following such a link makes
///   a recursive renderer (or any link-following traversal) descend forever.
/// * The walk never follows a symlink into a directory, so a symlinked directory is not
///   re-walked and its contents cannot be double-counted.
/// * Every entry beneath `root` counts toward `limits.max_files` (the root directory itself
///   does not) and every regular file's byte length counts toward `limits.max_bytes`;
///   exceeding either returns a terminal [`RepoError::CheckoutLimitExceeded`].
/// * A directory that cannot be read or that vanished mid-walk is a terminal
///   [`RepoError::RepositoryError`]: a tree that cannot be fully verified must never be
///   handed to a renderer, and re-walking it cannot help.
pub fn sanitize_worktree(root: &Path, limits: &WorktreeLimits) -> Result<(), RepoError> {
    let canonical_root = root.canonicalize().map_err(|source| {
        walk_error(
            source,
            format!("canonicalizing worktree root '{}'", root.display()),
        )
    })?;

    let mut pending: Vec<PathBuf> = vec![canonical_root.clone()];
    let mut files = 0usize;
    let mut bytes = 0u64;

    while let Some(dir) = pending.pop() {
        let read = std::fs::read_dir(&dir).map_err(|source| {
            walk_error(
                source,
                format!("reading worktree directory '{}'", dir.display()),
            )
        })?;

        for entry in read {
            let entry = entry.map_err(|source| {
                walk_error(
                    source,
                    format!("reading directory entry in '{}'", dir.display()),
                )
            })?;
            let path = entry.path();
            // `DirEntry::file_type` does not follow symlinks on Unix, so a symlink is
            // reported as a symlink (never as the target file/directory).
            let file_type = entry.file_type().map_err(|source| {
                walk_error(
                    source,
                    format!("inspecting worktree entry '{}'", path.display()),
                )
            })?;

            files = files
                .checked_add(1)
                .ok_or_else(|| RepoError::CheckoutLimitExceeded {
                    reason: "file count overflow".to_owned(),
                })?;
            if files > limits.max_files {
                return Err(RepoError::CheckoutLimitExceeded {
                    reason: format!(
                        "worktree contains more than {} filesystem entries",
                        limits.max_files
                    ),
                });
            }

            if file_type.is_symlink() {
                check_symlink(&path, &canonical_root)?;
            } else if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                let metadata = std::fs::symlink_metadata(&path).map_err(|source| {
                    walk_error(source, format!("reading metadata for '{}'", path.display()))
                })?;
                bytes = bytes.checked_add(metadata.len()).ok_or_else(|| {
                    RepoError::CheckoutLimitExceeded {
                        reason: "total byte count overflow".to_owned(),
                    }
                })?;
                if bytes > limits.max_bytes {
                    return Err(RepoError::CheckoutLimitExceeded {
                        reason: format!(
                            "worktree regular-file content exceeds {} bytes",
                            limits.max_bytes
                        ),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Sentinel target used when the link text itself could not be read.
///
/// [`RepoError::UnsafeSymlink`] always carries a target; when `read_link` fails there is no
/// target to report, so this placeholder accompanies an explicit reason instead of a silently
/// empty path.
const UNREADABLE_TARGET: &str = "<unreadable>";

/// Resolves one symlink and rejects it if its canonical target escapes `canonical_root` or
/// would make a link-following traversal recurse.
///
/// # Invariant
///
/// The canonical target of an accepted symlink must be **strictly inside** `canonical_root`
/// and must not be the link's own parent directory or any ancestor of it. The second half
/// rules out `link -> .`, `sub/link -> ..`, and `a/b/link -> a`, all of which resolve to an
/// ancestor of the link and would make a recursive renderer descend forever.
fn check_symlink(path: &Path, canonical_root: &Path) -> Result<(), RepoError> {
    let raw_target = match std::fs::read_link(path) {
        Ok(target) => target,
        Err(source) => {
            return Err(unsafe_symlink(
                path,
                Path::new(UNREADABLE_TARGET),
                format!("cannot read symlink: {source}"),
            ));
        }
    };

    let resolved = match std::fs::canonicalize(path) {
        Ok(resolved) => resolved,
        Err(source) => {
            return Err(unsafe_symlink(
                path,
                &raw_target,
                format!("symlink target cannot be resolved: {source}"),
            ));
        }
    };

    if !resolved.starts_with(canonical_root) {
        return Err(unsafe_symlink(
            path,
            &raw_target,
            "symlink target escapes the checkout root".to_owned(),
        ));
    }

    // `resolved.starts_with(canonical_root)` already passed, so a target that "is an ancestor
    // of the link" can only be the link's parent directory chain itself (e.g. `link -> .`).
    let link_dir = path.parent().unwrap_or(canonical_root);
    if link_dir.starts_with(&resolved) {
        return Err(unsafe_symlink(
            path,
            &raw_target,
            "symlink target is an ancestor of the link's parent directory, so following it \
             would recurse"
                .to_owned(),
        ));
    }

    Ok(())
}

/// Classifies a filesystem failure met while walking the tree.
///
/// A tree that cannot be inspected is untrustworthy: `PermissionDenied`, `NotADirectory`
/// (a tree entry was replaced by something that is not a directory) and `NotFound` (the
/// directory vanished mid-walk) are therefore terminal [`RepoError::RepositoryError`]s, not
/// retryable [`RepoError::Io`]s. Genuinely transient I/O (busy devices, ...) stays retryable.
fn walk_error(source: std::io::Error, context: String) -> RepoError {
    use std::io::ErrorKind;

    match source.kind() {
        ErrorKind::PermissionDenied | ErrorKind::NotADirectory | ErrorKind::NotFound => {
            RepoError::RepositoryError {
                message: format!("{context}: {source}"),
            }
        }
        _ => RepoError::Io { context, source },
    }
}

fn unsafe_symlink(path: &Path, target: &Path, reason: String) -> RepoError {
    RepoError::UnsafeSymlink {
        path: path.to_path_buf(),
        target: target.to_path_buf(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_limits() -> WorktreeLimits {
        WorktreeLimits::default()
    }

    #[test]
    fn default_limits_match_the_documented_budgets() {
        let limits = WorktreeLimits::new();
        assert_eq!(limits.max_files, DEFAULT_MAX_FILES);
        assert_eq!(limits.max_bytes, DEFAULT_MAX_BYTES);
        assert_eq!(
            WorktreeLimits::new().with_max_files(7).with_max_bytes(9),
            WorktreeLimits {
                max_files: 7,
                max_bytes: 9
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn valid_intra_repo_relative_symlink_passes() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("file.txt"), "content").expect("write file");
        std::os::unix::fs::symlink("file.txt", tmp.path().join("link.txt")).expect("create link");

        sanitize_worktree(tmp.path(), &default_limits()).expect("valid relative symlink must pass");
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_etc_passwd_fails_with_non_retryable_unsafe_symlink() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("file.txt"), "content").expect("write file");
        std::os::unix::fs::symlink("/etc/passwd", tmp.path().join("evil")).expect("create link");

        let err = sanitize_worktree(tmp.path(), &default_limits())
            .expect_err("symlink to /etc/passwd must be rejected");
        assert!(!err.is_retryable(), "escape must be terminal: {err}");
        match &err {
            RepoError::UnsafeSymlink {
                path,
                target,
                reason,
            } => {
                assert!(path.ends_with("evil"), "unexpected path: {path:?}");
                assert_eq!(target, &PathBuf::from("/etc/passwd"));
                assert!(!reason.is_empty());
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn chained_relative_escape_is_rejected() {
        let base = tempfile::tempdir().expect("create base dir");
        let root = base.path().join("worktree");
        let outside = base.path().join("outside");
        std::fs::create_dir_all(root.join("sub")).expect("mkdir sub");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        std::fs::write(outside.join("secret.txt"), "secret").expect("write outside file");
        // Resolves to <base>/outside/secret.txt, i.e. one directory above the root.
        std::os::unix::fs::symlink("../../outside/secret.txt", root.join("sub/link"))
            .expect("create link");

        let err = sanitize_worktree(&root, &default_limits())
            .expect_err("chained relative escape must be rejected");
        assert!(!err.is_retryable(), "escape must be terminal: {err}");
        match &err {
            RepoError::UnsafeSymlink {
                path,
                target,
                reason,
            } => {
                assert!(path.ends_with("sub/link"), "unexpected path: {path:?}");
                assert_eq!(target, &PathBuf::from("../../outside/secret.txt"));
                assert!(reason.contains("escapes"), "unexpected reason: {reason}");
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }
    }

    /// A sibling directory whose path *shares a string prefix* with the root
    /// (`<base>/worktree-evil` vs root `<base>/worktree`) must be treated as outside.
    ///
    /// This test fails the moment the containment check degrades from component-aware
    /// [`Path::starts_with`] to a naive `str::starts_with` on the rendered path.
    #[cfg(unix)]
    #[test]
    fn sibling_sharing_a_string_prefix_with_the_root_is_rejected() {
        let base = tempfile::tempdir().expect("create base dir");
        let root = base.path().join("worktree");
        let evil_sibling = base.path().join("worktree-evil");
        std::fs::create_dir_all(&root).expect("mkdir root");
        std::fs::create_dir_all(&evil_sibling).expect("mkdir evil sibling");
        std::fs::write(evil_sibling.join("secret"), "secret").expect("write sibling secret");
        std::os::unix::fs::symlink("../worktree-evil/secret", root.join("link"))
            .expect("create sibling link");
        assert!(
            evil_sibling
                .to_string_lossy()
                .starts_with(&*root.to_string_lossy()),
            "fixture precondition: the sibling's path must share the root's string prefix"
        );

        let err = sanitize_worktree(&root, &default_limits())
            .expect_err("a sibling sharing the root's string prefix must be rejected");
        assert!(!err.is_retryable(), "escape must be terminal: {err}");
        match &err {
            RepoError::UnsafeSymlink {
                path,
                target,
                reason,
            } => {
                assert!(path.ends_with("link"), "unexpected path: {path:?}");
                assert_eq!(target, &PathBuf::from("../worktree-evil/secret"));
                assert!(
                    reason.contains("escapes the checkout root"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }
    }

    /// An *absolute* target that resolves inside the root is legitimate and must pass.
    #[cfg(unix)]
    #[test]
    fn absolute_target_that_resolves_inside_the_root_is_accepted() {
        let base = tempfile::tempdir().expect("create base dir");
        let root = base.path().join("worktree");
        std::fs::create_dir_all(root.join("sub")).expect("mkdir sub");
        std::fs::write(root.join("sub/data.yaml"), "kind: ConfigMap\n").expect("write data");
        let absolute_target = root.join("sub/data.yaml");
        assert!(absolute_target.is_absolute());
        std::os::unix::fs::symlink(&absolute_target, root.join("abs-link"))
            .expect("create absolute link");

        sanitize_worktree(&root, &default_limits())
            .expect("an absolute symlink target inside the root must be accepted");
    }

    /// A symlink loop (`a -> b`, `b -> a`) can never be resolved and must be rejected.
    #[cfg(unix)]
    #[test]
    fn symlink_loop_is_rejected() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::os::unix::fs::symlink("b", tmp.path().join("a")).expect("create link a");
        std::os::unix::fs::symlink("a", tmp.path().join("b")).expect("create link b");

        let err = sanitize_worktree(tmp.path(), &default_limits())
            .expect_err("a symlink loop must be rejected");
        assert!(
            !err.is_retryable(),
            "a symlink loop must be terminal: {err}"
        );
        match &err {
            RepoError::UnsafeSymlink { reason, .. } => {
                assert!(
                    reason.contains("cannot be resolved"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }
    }

    /// A link to its own directory (or an ancestor of it) makes link-following traversal
    /// recurse forever, so it must be rejected even though it stays inside the root.
    #[cfg(unix)]
    #[test]
    fn link_to_its_own_directory_or_an_ancestor_is_rejected() {
        for (label, target, nested) in [
            ("self", ".", false),
            ("parent", "..", true),
            ("grandparent", "../..", true),
        ] {
            let base = tempfile::tempdir().expect("create base dir");
            let root = base.path().join("worktree");
            let link_dir = if nested {
                root.join("a/b")
            } else {
                root.clone()
            };
            std::fs::create_dir_all(&link_dir).expect("mkdir link dir");
            std::os::unix::fs::symlink(target, link_dir.join("loop"))
                .unwrap_or_else(|err| panic!("create {label} link: {err}"));

            let err = sanitize_worktree(&root, &default_limits())
                .err()
                .unwrap_or_else(|| panic!("{label} link must be rejected, got Ok"));
            assert!(!err.is_retryable(), "{label} link must be terminal: {err}");
            match &err {
                RepoError::UnsafeSymlink { reason, .. } => assert!(
                    reason.contains("ancestor"),
                    "unexpected reason for {label}: {reason}"
                ),
                other => panic!("expected UnsafeSymlink for {label}, got {other:?}"),
            }
        }
    }

    /// A directory the walk cannot read must fail terminally, never as a retryable I/O error.
    #[cfg(unix)]
    #[test]
    fn unreadable_directory_is_a_terminal_error() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("create temp dir");
        let locked = tmp.path().join("locked");
        std::fs::create_dir_all(&locked).expect("mkdir locked");
        std::fs::write(locked.join("inside.txt"), "x").expect("write inside");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("chmod locked");

        let result = sanitize_worktree(tmp.path(), &default_limits());
        // A privileged process (`root`) is not denied by mode `0o000`; there is nothing to
        // assert in that environment, and the check below keeps the test honest about it.
        let unreadable = std::fs::read_dir(&locked).is_err();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("restore chmod");
        if !unreadable {
            return;
        }

        let err = result.expect_err("an unreadable directory must fail the walk");
        assert!(
            matches!(err, RepoError::RepositoryError { .. }),
            "expected a terminal RepositoryError, got {err:?}"
        );
        assert!(
            !err.is_retryable(),
            "an unverifiable tree must never be retried as Io: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn broken_symlink_is_rejected() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::os::unix::fs::symlink("missing-target", tmp.path().join("dangling"))
            .expect("create dangling link");

        let err = sanitize_worktree(tmp.path(), &default_limits())
            .expect_err("broken symlink must be rejected");
        assert!(
            !err.is_retryable(),
            "broken symlink must be terminal: {err}"
        );
        match &err {
            RepoError::UnsafeSymlink {
                path,
                target,
                reason,
            } => {
                assert!(path.ends_with("dangling"), "unexpected path: {path:?}");
                assert_eq!(target, &PathBuf::from("missing-target"));
                assert!(
                    reason.contains("cannot be resolved"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }
    }

    #[test]
    fn max_files_exceeded_is_terminal() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        for index in 0..4 {
            std::fs::write(tmp.path().join(format!("f{index}")), "x").expect("write file");
        }

        let err = sanitize_worktree(tmp.path(), &WorktreeLimits::new().with_max_files(3))
            .expect_err("max_files budget must trip");
        assert!(
            matches!(err, RepoError::CheckoutLimitExceeded { .. }),
            "expected CheckoutLimitExceeded, got {err:?}"
        );
        assert!(!err.is_retryable(), "budget violation must be terminal");
    }

    #[test]
    fn max_bytes_exceeded_is_terminal() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        std::fs::write(tmp.path().join("big.txt"), "0123456789abcdef").expect("write file");

        let err = sanitize_worktree(tmp.path(), &WorktreeLimits::new().with_max_bytes(10))
            .expect_err("max_bytes budget must trip");
        assert!(
            matches!(err, RepoError::CheckoutLimitExceeded { .. }),
            "expected CheckoutLimitExceeded, got {err:?}"
        );
        assert!(!err.is_retryable(), "budget violation must be terminal");
    }
}
