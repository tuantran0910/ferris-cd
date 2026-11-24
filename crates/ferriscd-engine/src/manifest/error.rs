//! Error types for the manifest engine: YAML parsing, directory loading, and
//! offline normalization.
//!
//! Every error that names a specific manifest carries the repository-relative
//! source file path and, where the failure is scoped to one YAML document, the
//! 1-based document index.

/// Errors produced by the manifest engine (parse, load, normalize).
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The YAML text could not be parsed for the named document.
    #[error("{file}: document {doc}: {message}")]
    YamlParse {
        /// Repository-relative source file path.
        file: String,
        /// 1-based YAML document index within the file.
        doc: usize,
        /// Underlying parser message.
        message: String,
    },

    /// A whole-stream parser budget (aliases/depth/nodes/bytes/documents) was exceeded.
    #[error("{file}: YAML budget exceeded: {message}")]
    YamlBudget {
        /// Repository-relative source file path.
        file: String,
        /// Which budget was breached.
        message: String,
    },

    /// A parsed object failed manifest validation (missing or malformed fields).
    #[error("{file}: document {doc}: {message}")]
    Validation {
        /// Repository-relative source file path.
        file: String,
        /// 1-based YAML document index within the file.
        doc: usize,
        /// Validation failure description.
        message: String,
    },

    /// The resolved manifest path does not exist.
    #[error("manifest path not found: {path}")]
    NotFound { path: String },

    /// The resolved manifest path escapes the checkout root directory.
    #[error("manifest path '{path}' escapes checkout root '{root}'")]
    PathEscape { path: String, root: String },

    /// The resolved manifest path is not a supported file type.
    #[error("invalid manifest path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },

    /// Filesystem I/O failure while loading manifests.
    #[error("I/O error ({context}): {source}")]
    Io {
        /// Human-readable operation being performed.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A manifest file/directory limit (count or total bytes) was exceeded.
    #[error("manifest limit exceeded: {reason}")]
    LimitExceeded { reason: String },

    /// A resource failed offline normalization (e.g. malformed Secret fields).
    #[error("{file}: {message}")]
    Normalization { file: String, message: String },

    /// Two desired resources share the same version-agnostic GKNN key.
    #[error("duplicate resource key '{key}': defined in both '{file_a}' and '{file_b}'")]
    DuplicateResourceKey {
        /// Canonical `<group>/<kind>/<namespace>/<name>` key.
        key: String,
        /// First source file defining the key.
        file_a: String,
        /// Second source file defining the key.
        file_b: String,
    },
}

impl ManifestError {
    /// Returns `true` for transient failures that are safe to retry.
    ///
    /// Manifest parsing, validation, budget, path-escape, limit, and duplicate-key
    /// failures are all deterministic (terminal). Filesystem I/O is retryable **except**
    /// [`std::io::ErrorKind::InvalidData`], which a non-UTF-8 manifest produces and which
    /// can never be fixed by retrying.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Io { source, .. } => source.kind() != std::io::ErrorKind::InvalidData,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification_is_terminal_except_io() {
        let cases: Vec<(ManifestError, bool)> = vec![
            (
                ManifestError::YamlParse {
                    file: "a.yaml".into(),
                    doc: 1,
                    message: "boom".into(),
                },
                false,
            ),
            (
                ManifestError::YamlBudget {
                    file: "a.yaml".into(),
                    message: "nodes".into(),
                },
                false,
            ),
            (
                ManifestError::Validation {
                    file: "a.yaml".into(),
                    doc: 1,
                    message: "missing kind".into(),
                },
                false,
            ),
            (
                ManifestError::NotFound {
                    path: "missing".into(),
                },
                false,
            ),
            (
                ManifestError::PathEscape {
                    path: "../../etc".into(),
                    root: "/repo".into(),
                },
                false,
            ),
            (
                ManifestError::Io {
                    context: "reading".into(),
                    source: std::io::Error::other("disk"),
                },
                true,
            ),
            (
                ManifestError::Io {
                    context: "reading".into(),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, "not utf-8"),
                },
                false,
            ),
            (
                ManifestError::LimitExceeded {
                    reason: "too many files".into(),
                },
                false,
            ),
            (
                ManifestError::DuplicateResourceKey {
                    key: "v1/ConfigMap/ns/a".into(),
                    file_a: "a.yaml".into(),
                    file_b: "b.yaml".into(),
                },
                false,
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(err.is_retryable(), expected, "unexpected for {err}");
        }
    }

    #[test]
    fn error_messages_name_file_and_document() {
        let err = ManifestError::Validation {
            file: "apps/base.yaml".into(),
            doc: 3,
            message: "metadata.name is required".into(),
        };
        let text = err.to_string();
        assert!(text.contains("apps/base.yaml"), "{text}");
        assert!(text.contains("document 3"), "{text}");
        assert!(text.contains("metadata.name is required"), "{text}");
    }
}
