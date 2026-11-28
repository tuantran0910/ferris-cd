//! Git repository acquisition interface, domain types, and error classification.
//!
//! This module defines the backend-agnostic [`GitClient`] trait so the GitOps engine
//! and tests never depend directly on `gix` types.

pub(crate) mod auth;
pub mod cache;
pub mod error;
#[cfg(any(test, feature = "test-utils"))]
pub mod fake;
pub mod gix_client;
pub(crate) mod mirror;
pub mod oci;
pub mod registry;
pub mod sanitize;
pub mod types;

use std::future::Future;
use std::pin::Pin;

pub use cache::{RepoCache, RepoCacheConfig, RepoCacheGcReport};
pub use error::RepoError;
#[cfg(any(test, feature = "test-utils"))]
pub use fake::{FakeGitClient, FakeGitClientConfig, FakeHead, FakeStage};
pub use gix_client::{GixGitClient, GixGitClientConfig};
pub use mirror::{MirrorGcReport, MirrorLimits};
pub use oci::{
    DIGEST_HEX_LEN, DIGEST_PREFIX, FLUX_BUNDLE_MEDIA_TYPE, HELM_CHART_MEDIA_TYPE,
    MAX_MANIFEST_BYTES, OCI_IMAGE_LAYER_MEDIA_TYPE, OciClient, OciDescriptor, OciFuture,
    OciManifest, OciSource, OciUrlPolicy, ResolvedDigest, extract_artifact, extract_layer,
    extract_spooled_layer, is_supported_layer_media_type, sha256_digest, validate_digest,
    verify_digest,
};
#[cfg(any(test, feature = "test-utils"))]
pub use oci::{FakeOciClient, FakeOciClientConfig, artifact_manifest, tar_gzip_layer};
pub use registry::{RegistryOciClient, RegistryOciClientConfig};
pub use sanitize::{WorktreeLimits, sanitize_worktree};
pub(crate) use types::redact_oci_url_credentials;
pub use types::{
    GitSource, RepoCheckout, RepoCredentials, RepoUrlPolicy, ResolvedRevision, validate_commit_sha,
    validate_repo_url,
};

/// Boxed `Send` future returned by object-safe [`GitClient`] methods.
pub type RepoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RepoError>> + Send + 'a>>;

/// Asynchronous, object-safe interface for resolving Git revisions and checking out
/// immutable worktrees.
///
/// The trait is deliberately free of `gix` types: backends (and fakes) implement it with any
/// transport or object store. [`GixGitClient`] additionally maintains a **persistent per-URL bare
/// mirror / object store** (see [`mirror`]) behind these two methods so that materializing many
/// commits from one repository does not re-fetch shared history; that optimization is entirely
/// internal to the backend and is not part of this contract.
pub trait GitClient: Send + Sync {
    /// Resolves `src.target_revision` (branch, tag, `HEAD`, or commit SHA) into a
    /// canonical 40-character lowercase hex commit SHA.
    fn resolve_revision<'a>(
        &'a self,
        src: &'a GitSource,
        creds: &'a RepoCredentials,
    ) -> RepoFuture<'a, ResolvedRevision>;

    /// Materializes an immutable read-only worktree for the exact commit `sha` and
    /// returns a [`RepoCheckout`] handle.
    fn checkout<'a>(
        &'a self,
        src: &'a GitSource,
        sha: &'a str,
        creds: &'a RepoCredentials,
    ) -> RepoFuture<'a, RepoCheckout>;
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct LeaseGuard {
        dropped: Arc<AtomicBool>,
    }

    impl Drop for LeaseGuard {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct MockGitClient {
        sha: String,
    }

    impl GitClient for MockGitClient {
        fn resolve_revision<'a>(
            &'a self,
            src: &'a GitSource,
            _creds: &'a RepoCredentials,
        ) -> RepoFuture<'a, ResolvedRevision> {
            Box::pin(async move {
                src.validate(RepoUrlPolicy::Production)?;
                Ok(ResolvedRevision {
                    commit_sha: self.sha.clone(),
                    requested_ref: src.target_revision.clone(),
                })
            })
        }

        fn checkout<'a>(
            &'a self,
            src: &'a GitSource,
            sha: &'a str,
            _creds: &'a RepoCredentials,
        ) -> RepoFuture<'a, RepoCheckout> {
            Box::pin(async move {
                src.validate(RepoUrlPolicy::Production)?;
                validate_commit_sha(sha)?;
                Ok(RepoCheckout::new("/tmp/mock-checkout", sha))
            })
        }
    }

    #[tokio::test]
    async fn git_client_is_object_safe_and_works_behind_arc_dyn() {
        let sha = "abcdef0123456789abcdef0123456789abcdef01";
        let client: Arc<dyn GitClient> = Arc::new(MockGitClient {
            sha: sha.to_owned(),
        });
        let src = GitSource::new("https://github.com/ferris-cd/example.git", "main", "apps");
        let creds = RepoCredentials::Anonymous;

        let resolved = client
            .resolve_revision(&src, &creds)
            .await
            .expect("mock resolve_revision should succeed");
        assert_eq!(resolved.commit_sha, sha);
        assert_eq!(resolved.requested_ref, "main");

        let checkout = client
            .checkout(&src, &resolved.commit_sha, &creds)
            .await
            .expect("mock checkout should succeed");
        assert_eq!(checkout.root_dir(), Path::new("/tmp/mock-checkout"));
        assert_eq!(checkout.commit_sha(), sha);
    }

    #[test]
    fn repo_checkout_with_lease_drops_guard_on_drop() {
        let dropped = Arc::new(AtomicBool::new(false));
        let lease: Arc<dyn std::any::Any + Send + Sync> = Arc::new(LeaseGuard {
            dropped: Arc::clone(&dropped),
        });

        let checkout = RepoCheckout::with_lease(
            "/tmp/cached-worktree",
            "0123456789abcdef0123456789abcdef01234567",
            lease,
        );
        let dbg = format!("{checkout:?}");
        assert!(dbg.contains("has_lease: true"));
        assert!(!dropped.load(Ordering::SeqCst));

        drop(checkout);
        assert!(dropped.load(Ordering::SeqCst));

        let plain = RepoCheckout::new(
            "/tmp/plain-worktree",
            "0123456789abcdef0123456789abcdef01234567",
        );
        assert!(format!("{plain:?}").contains("has_lease: false"));
    }

    #[test]
    fn domain_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GitSource>();
        assert_send_sync::<ResolvedRevision>();
        assert_send_sync::<RepoCheckout>();
        assert_send_sync::<RepoCredentials>();
        assert_send_sync::<RepoError>();
    }

    /// Collects every `.rs` file under `dir` (no `walkdir` dependency for one test).
    fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                out.push(path);
            }
        }
    }

    /// **`T18.3` trap guard (finding N-B).** The rule is that no OCI crate type escapes
    /// `crates/ferriscd-engine/src/repo/`: the render/diff/sync pipeline must never grow a
    /// decompressor, a hasher, or a tar reader of its own, because a second implementation is how a
    /// digest check, a byte budget, or an entry rejection gets bypassed. A comment cannot hold that
    /// line, so this pins it structurally: outside `repo/`, the crate paths must not appear at all.
    ///
    /// Every workspace crate's `src` (and `tests`) is scanned — not just this one — since a
    /// `ferriscd-server` or `ferriscd-controller` file naming `flate2::` is exactly the leak.
    #[test]
    fn oci_crate_types_stay_inside_the_repo_module() {
        /// Crate paths that belong to `repo/` only: `sha2` (the digest) and `flate2` (the gzip
        /// decoder) are used by `repo/oci.rs`, and `tar` is the crate the in-house reader
        /// deliberately replaces — so the token is a forward guard that fires the day someone
        /// "just" adds it outside `repo/`.
        const FORBIDDEN: [&str; 3] = ["flate2::", "sha2::", "tar::"];

        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let crates_dir = crate_dir
            .parent()
            .expect("the engine crate lives in <workspace>/crates");
        let mut offenders: Vec<String> = Vec::new();
        let mut scanned = 0usize;

        for entry in std::fs::read_dir(crates_dir).expect("read the crates directory") {
            let candidate = entry.expect("crate directory entry").path();
            let mut files = Vec::new();
            rust_files(&candidate.join("src"), &mut files);
            rust_files(&candidate.join("tests"), &mut files);
            for file in files {
                let relative = file
                    .strip_prefix(&candidate)
                    .expect("every scanned file is under the crate it came from");
                if relative.starts_with("src/repo") {
                    continue;
                }
                let Ok(source) = std::fs::read_to_string(&file) else {
                    continue;
                };
                scanned += 1;
                for token in FORBIDDEN {
                    if source.contains(token) {
                        offenders.push(format!("{}: {token}", file.display()));
                    }
                }
            }
        }

        assert!(
            offenders.is_empty(),
            "OCI crate types escaped crates/ferriscd-engine/src/repo/: {offenders:?}"
        );
        // Guards against a vacuous pass: the walk must really reach the workspace, and the markers
        // the scan keys on must still exist where they belong.
        assert!(
            scanned > 50,
            "the source scan only saw {scanned} files; it is not walking the workspace"
        );
        let oci = crate_dir.join("src/repo/oci.rs");
        let oci_source = std::fs::read_to_string(&oci).expect("read src/repo/oci.rs");
        for token in ["flate2::", "sha2::"] {
            assert!(
                oci_source.contains(token),
                "{} no longer names {token}, so this scan would never catch it",
                oci.display()
            );
        }
    }
}
