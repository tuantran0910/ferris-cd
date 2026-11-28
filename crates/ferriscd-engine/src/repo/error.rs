//! Error types and retry classification for Git repository operations.

use std::path::PathBuf;

/// Errors returned by [`super::GitClient`] and repository validation helpers.
///
/// All variants are intentionally decoupled from any underlying Git library
/// (such as `gix`) so callers and fakes can construct and match them cleanly.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    /// DNS, TCP, TLS, or transient transport failure.
    #[error("network error: {message}")]
    Network { message: String },

    /// Connect, fetch, or authentication timeout.
    #[error("operation timed out: {message}")]
    Timeout { message: String },

    /// HTTP 5xx, 429 rate limits, or temporary remote server failures.
    #[error("{}", format_remote_server_error(*status, message))]
    RemoteServerError {
        status: Option<u16>,
        message: String,
    },

    /// Transient local cache or filesystem I/O error.
    #[error("I/O error ({context}): {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// Blocking worker task aborted or cancelled before completion.
    #[error("repository task cancelled: {message}")]
    TaskCancelled { message: String },

    /// Disallowed URL scheme, malformed URL, or embedded credentials.
    ///
    /// Note: `url` MUST have any embedded credentials redacted before constructing this variant.
    #[error("invalid repository URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },

    /// Invalid `target_revision` or `path` on [`super::GitSource`].
    #[error("invalid git source: {reason}")]
    InvalidSource { reason: String },

    /// Malformed commit SHA or revision syntax passed to checkout/resolve.
    #[error("invalid revision '{revision}': {reason}")]
    InvalidRevision { revision: String, reason: String },

    /// Requested branch, tag, or commit does not exist in the repository.
    #[error("revision '{revision}' not found")]
    RevisionNotFound { revision: String },

    /// Authentication rejected (HTTP 401/403, invalid token, bad SSH key/passphrase).
    #[error("authentication failed: {reason}")]
    AuthFailed { reason: String },

    /// Missing `known_hosts` or SSH host key mismatch.
    #[error("SSH host key verification failed for '{host}': {reason}")]
    HostKeyVerificationFailed { host: String, reason: String },

    /// Symlink detected inside worktree whose target escapes the checkout root.
    #[error("unsafe symlink at '{}' -> '{}': {reason}", path.display(), target.display())]
    UnsafeSymlink {
        path: PathBuf,
        target: PathBuf,
        reason: String,
    },

    /// Checkout file count or total byte limit exceeded.
    #[error("checkout limit exceeded: {reason}")]
    CheckoutLimitExceeded { reason: String },

    /// An OCI artifact's content did not match the immutable digest that was pinned for it.
    ///
    /// Terminal: the registry served bytes that are not the artifact the `Application` asked for
    /// (a moved tag, a corrupted mirror, or a proxy rewriting the body), and re-reading it cannot
    /// make it the right artifact.
    #[error("OCI artifact digest mismatch: expected {expected}, got {actual}")]
    OciDigestMismatch { expected: String, actual: String },

    /// An OCI artifact manifest (or a layer's declared size) is not usable.
    #[error("invalid OCI artifact: {reason}")]
    OciInvalidArtifact { reason: String },

    /// An OCI artifact layer carries a media type FerrisCD cannot render.
    #[error("unsupported OCI artifact media type '{media_type}'")]
    OciUnsupportedMediaType { media_type: String },

    /// A registry answered with a redirect, which FerrisCD deliberately does not follow.
    ///
    /// Terminal on purpose: the redirect is normally a CDN `Location`, and following it would mean
    /// carrying the `Authorization` header to a host the operator never configured. Naming the
    /// status (rather than reporting a generic `4xx`) is what lets an operator tell "this registry
    /// always redirects (ECR/GAR), put a proxy in front of it" apart from "this repository is
    /// missing".
    ///
    /// Note: `url` MUST have any embedded credentials redacted before constructing this variant, and
    /// the redirect `Location` is intentionally not part of the error.
    #[error(
        "the registry refused to serve {url} directly: HTTP {status} redirect (FerrisCD does not \
         follow registry redirects, because the Authorization header must not be carried to a host \
         the operator never configured)"
    )]
    RegistryRedirectRefused { status: u16, url: String },

    /// An archive entry is unsafe to materialize (tar-slip, link, device node, duplicate path).
    #[error("unsafe archive entry at '{}': {reason}", path.display())]
    UnsafeArchive { path: PathBuf, reason: String },

    /// Corrupt repository state or unsupported Git object/protocol error.
    #[error("repository error: {message}")]
    RepositoryError { message: String },
}

fn format_remote_server_error(status: Option<u16>, message: &str) -> String {
    match status {
        Some(code) => format!("remote server error (HTTP {code}): {message}"),
        None => format!("remote server error: {message}"),
    }
}

impl RepoError {
    /// Returns `true` if the failure is transient and safe to retry with backoff,
    /// or `false` if it is terminal and requires user or configuration intervention.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Network { .. }
            | Self::Timeout { .. }
            | Self::Io { .. }
            | Self::TaskCancelled { .. } => true,
            Self::RemoteServerError { status, .. } => {
                matches!(status, None | Some(408 | 429 | 500..=599))
            }
            Self::InvalidUrl { .. }
            | Self::InvalidSource { .. }
            | Self::InvalidRevision { .. }
            | Self::RevisionNotFound { .. }
            | Self::AuthFailed { .. }
            | Self::HostKeyVerificationFailed { .. }
            | Self::UnsafeSymlink { .. }
            | Self::CheckoutLimitExceeded { .. }
            | Self::OciDigestMismatch { .. }
            | Self::OciInvalidArtifact { .. }
            | Self::OciUnsupportedMediaType { .. }
            | Self::RegistryRedirectRefused { .. }
            | Self::UnsafeArchive { .. }
            | Self::RepositoryError { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification_truth_table() {
        let cases: Vec<(&str, RepoError, bool)> = vec![
            (
                "Network",
                RepoError::Network {
                    message: "connection reset".into(),
                },
                true,
            ),
            (
                "Timeout",
                RepoError::Timeout {
                    message: "timed out".into(),
                },
                true,
            ),
            (
                "RemoteServerError(Some(503))",
                RepoError::RemoteServerError {
                    status: Some(503),
                    message: "service unavailable".into(),
                },
                true,
            ),
            (
                "RemoteServerError(Some(500))",
                RepoError::RemoteServerError {
                    status: Some(500),
                    message: "internal server error".into(),
                },
                true,
            ),
            (
                "RemoteServerError(Some(429))",
                RepoError::RemoteServerError {
                    status: Some(429),
                    message: "too many requests".into(),
                },
                true,
            ),
            (
                "RemoteServerError(Some(408))",
                RepoError::RemoteServerError {
                    status: Some(408),
                    message: "request timeout".into(),
                },
                true,
            ),
            (
                "RemoteServerError(Some(400))",
                RepoError::RemoteServerError {
                    status: Some(400),
                    message: "bad request".into(),
                },
                false,
            ),
            (
                "RemoteServerError(None)",
                RepoError::RemoteServerError {
                    status: None,
                    message: "temporary failure".into(),
                },
                true,
            ),
            (
                "Io",
                RepoError::Io {
                    context: "reading pack".into(),
                    source: std::io::Error::other("disk busy"),
                },
                true,
            ),
            (
                "TaskCancelled",
                RepoError::TaskCancelled {
                    message: "worker aborted".into(),
                },
                true,
            ),
            (
                "InvalidUrl",
                RepoError::InvalidUrl {
                    url: "http://example.com/repo.git".into(),
                    reason: "plaintext HTTP disallowed".into(),
                },
                false,
            ),
            (
                "InvalidSource",
                RepoError::InvalidSource {
                    reason: "empty target_revision".into(),
                },
                false,
            ),
            (
                "InvalidRevision",
                RepoError::InvalidRevision {
                    revision: "not-a-sha".into(),
                    reason: "expected 40 lowercase hex chars".into(),
                },
                false,
            ),
            (
                "RevisionNotFound",
                RepoError::RevisionNotFound {
                    revision: "refs/heads/missing".into(),
                },
                false,
            ),
            (
                "AuthFailed",
                RepoError::AuthFailed {
                    reason: "HTTP 401".into(),
                },
                false,
            ),
            (
                "HostKeyVerificationFailed",
                RepoError::HostKeyVerificationFailed {
                    host: "github.com".into(),
                    reason: "missing known_hosts".into(),
                },
                false,
            ),
            (
                "UnsafeSymlink",
                RepoError::UnsafeSymlink {
                    path: PathBuf::from("secret.yaml"),
                    target: PathBuf::from("/etc/passwd"),
                    reason: "escapes root".into(),
                },
                false,
            ),
            (
                "CheckoutLimitExceeded",
                RepoError::CheckoutLimitExceeded {
                    reason: "too many files".into(),
                },
                false,
            ),
            (
                "OciDigestMismatch",
                RepoError::OciDigestMismatch {
                    expected: format!("sha256:{}", "a".repeat(64)),
                    actual: format!("sha256:{}", "b".repeat(64)),
                },
                false,
            ),
            (
                "OciInvalidArtifact",
                RepoError::OciInvalidArtifact {
                    reason: "schemaVersion must be 2".into(),
                },
                false,
            ),
            (
                "OciUnsupportedMediaType",
                RepoError::OciUnsupportedMediaType {
                    media_type: "application/vnd.example".into(),
                },
                false,
            ),
            (
                "RegistryRedirectRefused",
                RepoError::RegistryRedirectRefused {
                    status: 307,
                    url: "https://ghcr.io/v2/org/chart/blobs/sha256:abc".into(),
                },
                false,
            ),
            (
                "UnsafeArchive",
                RepoError::UnsafeArchive {
                    path: PathBuf::from("../../etc/passwd"),
                    reason: "traversal".into(),
                },
                false,
            ),
            (
                "RepositoryError",
                RepoError::RepositoryError {
                    message: "corrupt packfile".into(),
                },
                false,
            ),
        ];

        for (name, err, expected) in cases {
            assert_eq!(
                err.is_retryable(),
                expected,
                "unexpected retryable classification for {name}: {err}"
            );
        }
    }

    #[test]
    fn remote_server_error_display_handles_optional_status() {
        let with_status = RepoError::RemoteServerError {
            status: Some(429),
            message: "rate limited".into(),
        };
        assert_eq!(
            with_status.to_string(),
            "remote server error (HTTP 429): rate limited"
        );

        let without_status = RepoError::RemoteServerError {
            status: None,
            message: "upstream reset".into(),
        };
        assert_eq!(
            without_status.to_string(),
            "remote server error: upstream reset"
        );
    }
}
