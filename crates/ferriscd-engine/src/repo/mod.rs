//! Git repository acquisition interface, domain types, and error classification.
//!
//! This module defines the backend-agnostic [`GitClient`] trait so the GitOps engine
//! and tests never depend directly on `gix` types.

pub mod error;
pub mod types;

use std::future::Future;
use std::pin::Pin;

pub use error::RepoError;
pub use types::{
    GitSource, RepoCheckout, RepoCredentials, RepoUrlPolicy, ResolvedRevision, validate_commit_sha,
    validate_repo_url,
};

/// Boxed `Send` future returned by object-safe [`GitClient`] methods.
pub type RepoFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RepoError>> + Send + 'a>>;

/// Asynchronous, object-safe interface for resolving Git revisions and checking out
/// immutable worktrees.
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
}
