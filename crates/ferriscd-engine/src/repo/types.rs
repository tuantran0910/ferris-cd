//! Domain types, credential redaction, and input validation for Git repositories.

use std::fmt;
use std::net::Ipv6Addr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::error::RepoError;

/// Policy controlling which repository URL schemes are accepted by [`validate_repo_url`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RepoUrlPolicy {
    /// Production policy: allows only `https://`, `ssh://`, and SCP-style SSH (`user@host:path`).
    /// Rejects `file://`, `http://`, `git://`, bare local paths, and embedded credentials.
    #[default]
    Production,
    /// Test/local development policy: allows everything in [`RepoUrlPolicy::Production`]
    /// plus `file://` URLs and local filesystem paths. Still rejects `http://`, `git://`,
    /// unknown schemes, and embedded credentials.
    AllowLocal,
}

/// Declarative reference to a Git repository, target revision, and manifest sub-path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitSource {
    /// Repository clone URL (or local path when permitted by [`RepoUrlPolicy::AllowLocal`]).
    pub repo_url: String,
    /// Branch, tag, `HEAD`, or commit SHA to resolve and check out.
    pub target_revision: String,
    /// Relative sub-directory inside the repository (`""` or `"."` for repository root).
    pub path: String,
}

impl GitSource {
    /// Constructs a new [`GitSource`].
    #[must_use]
    pub fn new(
        repo_url: impl Into<String>,
        target_revision: impl Into<String>,
        path: impl Into<String>,
    ) -> Self {
        Self {
            repo_url: repo_url.into(),
            target_revision: target_revision.into(),
            path: path.into(),
        }
    }

    /// Validates `repo_url`, `target_revision`, and `path` against `policy`.
    pub fn validate(&self, policy: RepoUrlPolicy) -> Result<(), RepoError> {
        validate_repo_url(&self.repo_url, policy)?;
        validate_target_revision(&self.target_revision)?;
        validate_source_path(&self.path)?;
        Ok(())
    }
}

/// Result of resolving a symbolic ref (branch, tag, `HEAD`) or SHA to a canonical commit OID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResolvedRevision {
    /// Canonical 40-character lowercase hex Git commit SHA.
    pub commit_sha: String,
    /// Original revision string requested by the caller (e.g., `"main"`, `"v1.2.3"`).
    pub requested_ref: String,
}

/// Checked-out immutable worktree directory for a specific resolved commit SHA.
///
/// Fields are private so callers cannot move `root_dir` out and drop the internal
/// cache lease guard prematurely.
pub struct RepoCheckout {
    root_dir: PathBuf,
    commit_sha: String,
    _lease: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

impl RepoCheckout {
    /// Creates a [`RepoCheckout`] without an attached cache lease.
    #[must_use]
    pub fn new(root_dir: impl Into<PathBuf>, commit_sha: impl Into<String>) -> Self {
        Self {
            root_dir: root_dir.into(),
            commit_sha: commit_sha.into(),
            _lease: None,
        }
    }

    /// Creates a [`RepoCheckout`] holding an opaque RAII cache lease for the lifetime of `self`.
    #[must_use]
    pub fn with_lease(
        root_dir: impl Into<PathBuf>,
        commit_sha: impl Into<String>,
        lease: Arc<dyn std::any::Any + Send + Sync>,
    ) -> Self {
        Self {
            root_dir: root_dir.into(),
            commit_sha: commit_sha.into(),
            _lease: Some(lease),
        }
    }

    /// Returns the root directory of the checked-out worktree.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns the canonical commit SHA corresponding to this checkout.
    #[must_use]
    pub fn commit_sha(&self) -> &str {
        &self.commit_sha
    }
}

impl fmt::Debug for RepoCheckout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepoCheckout")
            .field("root_dir", &self.root_dir)
            .field("commit_sha", &self.commit_sha)
            .field("has_lease", &self._lease.is_some())
            .finish()
    }
}

/// Authentication credentials for accessing a Git repository.
///
/// Deliberately does NOT implement `Serialize` and uses custom `Debug`/`Display`
/// implementations so secret material is never printed in logs or error reports.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum RepoCredentials {
    /// Unauthenticated access (public repositories or local test fixtures).
    #[default]
    Anonymous,
    /// HTTPS bearer / personal access token authentication.
    HttpToken { token: String },
    /// HTTPS basic username/password authentication.
    HttpBasic { username: String, password: String },
    /// SSH private key authentication with optional passphrase and `known_hosts` data.
    SshKey {
        private_key_pem: String,
        passphrase: Option<String>,
        known_hosts: Option<String>,
    },
}

impl fmt::Debug for RepoCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => f.write_str("RepoCredentials::Anonymous"),
            Self::HttpToken { .. } => f
                .debug_struct("HttpToken")
                .field("token", &"[REDACTED]")
                .finish(),
            Self::HttpBasic { .. } => f
                .debug_struct("HttpBasic")
                .field("username", &"[REDACTED]")
                .field("password", &"[REDACTED]")
                .finish(),
            Self::SshKey {
                passphrase,
                known_hosts,
                ..
            } => f
                .debug_struct("SshKey")
                .field("private_key_pem", &"[REDACTED]")
                .field("passphrase", &passphrase.as_ref().map(|_| "[REDACTED]"))
                .field("known_hosts", &known_hosts.as_ref().map(|_| "[PRESENT]"))
                .finish(),
        }
    }
}

impl fmt::Display for RepoCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Anonymous => "anonymous",
            Self::HttpToken { .. } => "http-token",
            Self::HttpBasic { .. } => "http-basic",
            Self::SshKey { .. } => "ssh-key",
        };
        f.write_str(label)
    }
}

/// Validates a canonical 40-character lowercase ASCII hexadecimal Git commit SHA.
pub fn validate_commit_sha(sha: &str) -> Result<(), RepoError> {
    if sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(RepoError::InvalidRevision {
            revision: sha.to_owned(),
            reason: "commit SHA must be exactly 40 lowercase hexadecimal characters".to_owned(),
        })
    }
}

/// Validates a repository URL or local path under the provided [`RepoUrlPolicy`].
///
/// Any embedded credentials in rejected URLs are redacted before constructing
/// [`RepoError::InvalidUrl`].
pub fn validate_repo_url(url: &str, policy: RepoUrlPolicy) -> Result<(), RepoError> {
    if url.trim().is_empty() {
        return Err(RepoError::InvalidUrl {
            url: String::new(),
            reason: "repository URL must not be empty".to_owned(),
        });
    }

    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(url),
            reason: "repository URL must not contain whitespace or control characters".to_owned(),
        });
    }

    if url.starts_with('-') {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(url),
            reason: "repository URL must not start with '-'".to_owned(),
        });
    }

    if let Some((scheme, rest)) = url.split_once("://") {
        return validate_scheme_url(url, scheme, rest, policy);
    }

    if let Some((prefix, _)) = url.split_once("::")
        && !prefix.is_empty()
        && prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'+'))
    {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(url),
            reason: format!("git '{prefix}::' remote helper URLs are disallowed"),
        });
    }

    if let Some((user, after_at)) = url.split_once('@')
        && !user.contains('/')
        && after_at.contains(':')
    {
        return validate_scp_ssh_url(url, user, after_at);
    }

    match policy {
        RepoUrlPolicy::Production => Err(RepoError::InvalidUrl {
            url: redact_url_credentials(url),
            reason: "local filesystem paths are disallowed under production URL policy".to_owned(),
        }),
        RepoUrlPolicy::AllowLocal => Ok(()),
    }
}

fn validate_scheme_url(
    raw_url: &str,
    scheme: &str,
    rest: &str,
    policy: RepoUrlPolicy,
) -> Result<(), RepoError> {
    match scheme.to_ascii_lowercase().as_str() {
        "https" => {
            let authority = rest.split_once(['/', '?', '#']).map_or(rest, |(a, _)| a);
            if authority.contains('@') {
                return Err(RepoError::InvalidUrl {
                    url: redact_url_credentials(raw_url),
                    reason: "embedded credentials in HTTPS URLs are disallowed".to_owned(),
                });
            }
            validate_authority_host(raw_url, authority)
        }
        "ssh" => {
            let authority = rest.split_once(['/', '?', '#']).map_or(rest, |(a, _)| a);
            if let Some((userinfo, host_port)) = authority.split_once('@') {
                if host_port.contains('@') {
                    return Err(RepoError::InvalidUrl {
                        url: redact_url_credentials(raw_url),
                        reason: "malformed SSH authority with multiple '@' characters".to_owned(),
                    });
                }
                if userinfo.is_empty() {
                    return Err(RepoError::InvalidUrl {
                        url: redact_url_credentials(raw_url),
                        reason: "SSH username before '@' must not be empty".to_owned(),
                    });
                }
                if userinfo.contains(':') {
                    return Err(RepoError::InvalidUrl {
                        url: redact_url_credentials(raw_url),
                        reason: "embedded password in SSH URLs is disallowed".to_owned(),
                    });
                }
                if userinfo.starts_with('-') {
                    return Err(RepoError::InvalidUrl {
                        url: redact_url_credentials(raw_url),
                        reason: "SSH username must not start with '-'".to_owned(),
                    });
                }
                if userinfo.contains(['[', ']']) {
                    return Err(RepoError::InvalidUrl {
                        url: redact_url_credentials(raw_url),
                        reason: "SSH username must not contain '[' or ']'".to_owned(),
                    });
                }
                validate_authority_host(raw_url, host_port)
            } else {
                validate_authority_host(raw_url, authority)
            }
        }
        "file" => match policy {
            RepoUrlPolicy::Production => Err(RepoError::InvalidUrl {
                url: redact_url_credentials(raw_url),
                reason: "'file://' URLs are disallowed under production URL policy".to_owned(),
            }),
            RepoUrlPolicy::AllowLocal => {
                if rest.is_empty() {
                    return Err(RepoError::InvalidUrl {
                        url: redact_url_credentials(raw_url),
                        reason: "'file://' URL must specify a non-empty path".to_owned(),
                    });
                }
                if !rest.starts_with('/') {
                    let authority = rest.split_once(['/', '?', '#']).map_or(rest, |(a, _)| a);
                    if authority.contains('@') {
                        return Err(RepoError::InvalidUrl {
                            url: redact_url_credentials(raw_url),
                            reason: "embedded credentials in 'file://' URLs are disallowed"
                                .to_owned(),
                        });
                    }
                }
                Ok(())
            }
        },
        _ => Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: format!("unsupported URL scheme '{scheme}'"),
        }),
    }
}

pub(super) fn validate_authority_host(raw_url: &str, authority: &str) -> Result<(), RepoError> {
    if authority.is_empty() {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "URL host must not be empty".to_owned(),
        });
    }

    if let Some(after_bracket) = authority.strip_prefix('[') {
        let Some((ipv6_host, suffix)) = after_bracket.split_once(']') else {
            return Err(RepoError::InvalidUrl {
                url: redact_url_credentials(raw_url),
                reason: "unclosed IPv6 host literal".to_owned(),
            });
        };
        if ipv6_host.parse::<Ipv6Addr>().is_err() {
            return Err(RepoError::InvalidUrl {
                url: redact_url_credentials(raw_url),
                reason: "invalid IPv6 host literal".to_owned(),
            });
        }
        if !suffix.is_empty() {
            let Some(port) = suffix.strip_prefix(':') else {
                return Err(RepoError::InvalidUrl {
                    url: redact_url_credentials(raw_url),
                    reason: "invalid authority after IPv6 literal".to_owned(),
                });
            };
            validate_port(raw_url, port)?;
        }
        return Ok(());
    }

    let (host, port_opt) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };

    if host.is_empty() {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "URL host must not be empty".to_owned(),
        });
    }

    if host.starts_with('-') {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "URL host must not start with '-'".to_owned(),
        });
    }

    if host.contains(['\\', ';', '[', ']']) {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "URL host contains disallowed characters".to_owned(),
        });
    }

    if let Some(port) = port_opt {
        validate_port(raw_url, port)?;
    }

    Ok(())
}

fn validate_port(raw_url: &str, port: &str) -> Result<(), RepoError> {
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || !port.parse::<u16>().is_ok_and(|p| p > 0)
    {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "URL port must be a non-zero 16-bit integer".to_owned(),
        });
    }
    Ok(())
}

fn validate_scp_ssh_url(raw_url: &str, user: &str, after_at: &str) -> Result<(), RepoError> {
    if user.is_empty() || user.contains([':', '@', '\\', '[', ']']) || user.starts_with('-') {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "invalid SCP-style SSH username or embedded credentials".to_owned(),
        });
    }

    let Some((host, path)) = after_at.split_once(':') else {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "SCP-style SSH URL must include ':<path>'".to_owned(),
        });
    };

    if host.is_empty()
        || host.contains(['/', '@', '\\', '[', ']'])
        || !host
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "SCP-style SSH host must be non-empty and start with an alphanumeric character"
                .to_owned(),
        });
    }

    if path.is_empty() || path.contains('\\') {
        return Err(RepoError::InvalidUrl {
            url: redact_url_credentials(raw_url),
            reason: "SCP-style SSH path must be non-empty and must not contain '\\'".to_owned(),
        });
    }

    Ok(())
}

/// Returns `url` with any embedded `user:password@`/`token@` userinfo replaced by `[REDACTED]`.
///
/// Every [`RepoError::InvalidUrl`] this module (and [`super::oci`]) builds must call this: the
/// message reaches `Application.status`, Events, and logs, so a rejected URL must never carry the
/// credential that made it rejected. Only the authority's userinfo is a secret; the host, port,
/// path, and scheme are kept so the error still names the offending reference.
///
/// A **scheme-less** `user@host` is kept as written: `git@github.com:org/repo.git` is the
/// SCP-style SSH spelling, where `git` is a login name and not a credential. The scheme-less rule
/// therefore only redacts userinfo that carries a `:` (finding M-A pins the registry counterpart,
/// [`redact_oci_url_credentials`], which cannot rely on that).
pub(super) fn redact_url_credentials(url: &str) -> String {
    redact_userinfo(url, SCP_STYLE_USER_IS_KEPT)
}

/// Redacts userinfo in a **registry** reference, including a scheme-less one.
///
/// Identical to [`redact_url_credentials`] except that a scheme-less `user@host` is userinfo too.
/// The difference is not cosmetic: a reference that forgot its `oci://` reaches the "must be
/// absolute" rejection as `token@ghcr.io/org/chart`, and the Git rule would keep it intact because
/// there is no `:`. A registry reference has no SCP-style spelling — every `@` before the end of
/// the authority is a credential (finding M-A).
pub(super) fn redact_oci_url_credentials(url: &str) -> String {
    redact_userinfo(url, false)
}

/// `true` for the Git rule: a scheme-less `user@host` may be SCP-style SSH and is kept.
const SCP_STYLE_USER_IS_KEPT: bool = true;

/// Shared body of [`redact_url_credentials`] and [`redact_oci_url_credentials`].
///
/// An optional `scheme://` is split off, the authority runs to the first `/`, `?`, or `#`, and the
/// **last** `@` in it is the userinfo/host boundary (userinfo may contain an unescaped `@`; the
/// host cannot).
fn redact_userinfo(url: &str, keep_scp_style: bool) -> String {
    if let Some((scheme, rest)) = url.split_once("://") {
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, suffix) = rest.split_at(auth_end);
        if let Some((_, host_part)) = authority.rsplit_once('@') {
            return format!("{scheme}://[REDACTED]@{host_part}{suffix}");
        }
        return url.to_owned();
    }

    let head_end = url.find(['/', '?', '#']).unwrap_or(url.len());
    let (head, suffix) = url.split_at(head_end);
    if let Some((userinfo, host_part)) = head.rsplit_once('@')
        && (!keep_scp_style || userinfo.contains(':'))
    {
        return format!("[REDACTED]@{host_part}{suffix}");
    }

    url.to_owned()
}

fn validate_target_revision(rev: &str) -> Result<(), RepoError> {
    if rev.is_empty() {
        return Err(RepoError::InvalidSource {
            reason: "target_revision must not be empty".to_owned(),
        });
    }

    if rev.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(RepoError::InvalidSource {
            reason: "target_revision must not contain whitespace or control characters".to_owned(),
        });
    }

    if rev.starts_with('-') {
        return Err(RepoError::InvalidSource {
            reason: "target_revision must not start with '-'".to_owned(),
        });
    }

    if rev.contains('\\') {
        return Err(RepoError::InvalidSource {
            reason: "target_revision must not contain '\\'".to_owned(),
        });
    }

    if rev == "@"
        || rev == "."
        || rev.starts_with('/')
        || rev.ends_with('/')
        || rev.ends_with('.')
        || rev.ends_with(".lock")
        || rev.contains("..")
        || rev.contains("@{")
        || rev.contains("//")
        || rev.contains("/.")
        || rev.contains(['~', '^', ':', '?', '*', '['])
    {
        return Err(RepoError::InvalidSource {
            reason: "target_revision contains invalid Git ref syntax".to_owned(),
        });
    }

    Ok(())
}

pub(super) fn validate_source_path(path: &str) -> Result<(), RepoError> {
    if path.chars().any(char::is_control) {
        return Err(RepoError::InvalidSource {
            reason: "source path must not contain control characters".to_owned(),
        });
    }

    if path.contains('\\') {
        return Err(RepoError::InvalidSource {
            reason: "source path must not contain '\\'".to_owned(),
        });
    }

    if path.starts_with('/') {
        return Err(RepoError::InvalidSource {
            reason: "source path must be relative (cannot start with '/')".to_owned(),
        });
    }

    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(RepoError::InvalidSource {
            reason: "source path must not contain a Windows drive prefix".to_owned(),
        });
    }

    if path.split(['/', '\\']).any(|segment| segment == "..") {
        return Err(RepoError::InvalidSource {
            reason: "source path must not contain '..' traversal segments".to_owned(),
        });
    }

    for component in Path::new(path).components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(RepoError::InvalidSource {
                    reason: "source path must be a relative path without parent traversal"
                        .to_owned(),
                });
            }
            Component::CurDir | Component::Normal(_) => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_debug_and_display_redact_all_secrets() {
        let anon = RepoCredentials::Anonymous;
        assert_eq!(format!("{anon:?}"), "RepoCredentials::Anonymous");
        assert_eq!(format!("{anon}"), "anonymous");

        let token_secret = "ghp_super_secret_token_987654";
        let token = RepoCredentials::HttpToken {
            token: token_secret.to_owned(),
        };
        let token_dbg = format!("{token:?}");
        let token_pretty = format!("{token:#?}");
        assert!(!token_dbg.contains(token_secret));
        assert!(!token_pretty.contains(token_secret));
        assert!(token_dbg.contains("[REDACTED]"));
        assert_eq!(format!("{token}"), "http-token");

        let basic_user = "ci-bot-user";
        let basic_pass = "super-secret-password-xyz";
        let basic = RepoCredentials::HttpBasic {
            username: basic_user.to_owned(),
            password: basic_pass.to_owned(),
        };
        let basic_dbg = format!("{basic:?}");
        let basic_pretty = format!("{basic:#?}");
        assert!(!basic_dbg.contains(basic_user));
        assert!(!basic_dbg.contains(basic_pass));
        assert!(!basic_pretty.contains(basic_user));
        assert!(!basic_pretty.contains(basic_pass));
        assert!(basic_dbg.contains("[REDACTED]"));
        assert_eq!(format!("{basic}"), "http-basic");

        let pem_secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_KEY_BODY\n-----END OPENSSH PRIVATE KEY-----";
        let pass_secret = "ssh-passphrase-secret";
        let kh_secret = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAASECRET";
        let ssh_full = RepoCredentials::SshKey {
            private_key_pem: pem_secret.to_owned(),
            passphrase: Some(pass_secret.to_owned()),
            known_hosts: Some(kh_secret.to_owned()),
        };
        let ssh_dbg = format!("{ssh_full:?}");
        let ssh_pretty = format!("{ssh_full:#?}");
        for s in [&ssh_dbg, &ssh_pretty] {
            assert!(!s.contains(pem_secret));
            assert!(!s.contains("SECRET_KEY_BODY"));
            assert!(!s.contains(pass_secret));
            assert!(!s.contains(kh_secret));
            assert!(s.contains("[REDACTED]"));
            assert!(s.contains("[PRESENT]"));
        }
        assert_eq!(format!("{ssh_full}"), "ssh-key");

        let ssh_minimal = RepoCredentials::SshKey {
            private_key_pem: pem_secret.to_owned(),
            passphrase: None,
            known_hosts: None,
        };
        let ssh_min_dbg = format!("{ssh_minimal:?}");
        assert!(!ssh_min_dbg.contains(pem_secret));
        assert!(ssh_min_dbg.contains("None"));
        assert!(ssh_min_dbg.contains("[REDACTED]"));
    }

    #[test]
    fn url_validation_production_vs_allow_local() {
        let valid_remote = [
            "https://github.com/ferris-cd/manifests.git",
            "HTTPS://github.com/ferris-cd/manifests.git",
            "https://github.com:443/ferris-cd/manifests",
            "https://[::1]:8443/org/repo.git",
            "ssh://git@github.com/ferris-cd/manifests.git",
            "SSH://git@github.com/ferris-cd/manifests.git",
            "ssh://git@github.com:2222/ferris-cd/manifests.git",
            "ssh://github.com/ferris-cd/manifests.git",
            "https://github.com/org/repo@v1",
            "git@github.com:ferris-cd/manifests.git",
        ];

        for url in valid_remote {
            assert!(
                validate_repo_url(url, RepoUrlPolicy::Production).is_ok(),
                "expected Production to accept {url}"
            );
            assert!(
                validate_repo_url(url, RepoUrlPolicy::AllowLocal).is_ok(),
                "expected AllowLocal to accept {url}"
            );
        }

        let local_only = [
            "file:///tmp/my-repo",
            "FILE:///tmp/my-repo",
            "file://localhost/tmp/my-repo",
            "/tmp/my-repo",
            "./fixtures/repo",
            "relative/repo",
            "ab😀",
            "abc€",
        ];

        for url in local_only {
            assert!(
                validate_repo_url(url, RepoUrlPolicy::Production).is_err(),
                "expected Production to reject {url}"
            );
            assert!(
                validate_repo_url(url, RepoUrlPolicy::AllowLocal).is_ok(),
                "expected AllowLocal to accept {url}"
            );
        }

        let always_rejected = [
            "",
            "   ",
            "https://github.com/org/repo with space",
            "https://github.com/org/repo\n",
            "/tmp/repo\0evil",
            "-u/tmp/repo",
            "--upload-pack=evil",
            "http://github.com/org/repo.git",
            "HTTP://github.com/org/repo.git",
            "git://github.com/org/repo.git",
            "ftp://example.com/repo.git",
            "ext::sh -c evil",
            "fd::17",
            "fd::/tmp/repo",
            "file://",
            "FILE://",
            "https:///org/repo.git",
            "https://:443/org/repo.git",
            "https://-evil.example/repo.git",
            "https://[-oProxyCommand=id]/repo",
            "https://[not-ipv6]/repo",
            "https://evil.com\\path/repo",
            "https://evil.com;id/repo",
            "https://github.com:0/org/repo.git",
            "https://github.com:999999999/org/repo.git",
            "https://github.com:+443/org/repo.git",
            "ssh://@github.com/org/repo.git",
            "ssh://-oProxyCommand=id@github.com/org/repo.git",
            "ssh://[::1@evil]/repo",
            "user@-oProxyCommand=id:repo",
            "-user@github.com:org/repo",
            "evil\\user@github.com:org/repo",
            "git@github.com\\evil:org/repo",
            "git@github.com:org\\repo",
            "git@github.com:",
        ];

        for url in always_rejected {
            assert!(
                validate_repo_url(url, RepoUrlPolicy::Production).is_err(),
                "expected Production to reject {url:?}"
            );
            assert!(
                validate_repo_url(url, RepoUrlPolicy::AllowLocal).is_err(),
                "expected AllowLocal to reject {url:?}"
            );
        }
    }

    #[test]
    fn url_validation_rejects_and_redacts_embedded_credentials() {
        let both_policies_cases = [
            (
                "https://alice:top_secret_pw@github.com/org/repo.git",
                &["top_secret_pw"][..],
            ),
            (
                "https://ghp_secret_token@github.com/org/repo.git",
                &["ghp_secret_token"][..],
            ),
            (
                "ssh://bob:ssh_secret_pw@github.com/org/repo.git",
                &["ssh_secret_pw"][..],
            ),
            (
                "alice:scp_secret_pw@github.com:org/repo.git",
                &["scp_secret_pw"][..],
            ),
            (
                "alice:p@ssword@github.com:org/repo.git",
                &["p@ssword", "ssword"][..],
            ),
            ("file://user:secret@localhost/tmp/repo", &["secret"][..]),
            ("FILE://user:secret@localhost/tmp/repo", &["secret"][..]),
        ];

        for (url, secrets) in both_policies_cases {
            for policy in [RepoUrlPolicy::Production, RepoUrlPolicy::AllowLocal] {
                let err = validate_repo_url(url, policy)
                    .expect_err("embedded credentials must be rejected");
                let disp = format!("{err}");
                let dbg = format!("{err:?}");
                for secret in secrets {
                    assert!(
                        !disp.contains(secret) && !dbg.contains(secret),
                        "secret {secret:?} leaked in error output for {url}: {disp} / {dbg}"
                    );
                }
                assert!(
                    disp.contains("[REDACTED]"),
                    "expected [REDACTED] placeholder in {disp}"
                );
            }
        }

        let prod_only_case = "alice:p@ssword@github.com/org/repo.git";
        let err = validate_repo_url(prod_only_case, RepoUrlPolicy::Production)
            .expect_err("non-scheme credentialed path must be rejected in Production");
        let disp = format!("{err}");
        let dbg = format!("{err:?}");
        for secret in ["p@ssword", "ssword"] {
            assert!(
                !disp.contains(secret) && !dbg.contains(secret),
                "secret {secret:?} leaked in error output for {prod_only_case}: {disp} / {dbg}"
            );
        }
        assert!(disp.contains("[REDACTED]"));
    }

    #[test]
    fn git_source_validate_checks_revision_and_path() {
        let valid_sources = [
            GitSource::new("https://github.com/org/repo.git", "main", ""),
            GitSource::new("https://github.com/org/repo.git", "v1.2.3", "."),
            GitSource::new("https://github.com/org/repo.git", "release/2026-01", "apps"),
            GitSource::new("https://github.com/org/repo.git", "release@v1", "apps"),
            GitSource::new(
                "https://github.com/org/repo.git",
                "0123456789abcdef0123456789abcdef01234567",
                "apps/prod/overlays",
            ),
            GitSource::new("https://github.com/org/repo.git", "HEAD", "./apps/dev"),
        ];
        for src in valid_sources {
            assert!(
                src.validate(RepoUrlPolicy::Production).is_ok(),
                "expected valid GitSource: {src:?}"
            );
        }

        let bad_revisions = [
            "",
            "main branch",
            "main\n",
            "main\0",
            "-b",
            "--upload-pack=evil",
            "feature\\branch",
            "main..feature",
            "HEAD@{1}",
            "@",
            ".",
            "a//b",
            "/main",
            "main/",
            "main.",
            "a/.hidden",
            "main.lock",
            "HEAD~1",
            "HEAD^1",
            "refs:main",
            "v1?",
            "v1*",
            "v1[0]",
        ];
        for rev in bad_revisions {
            let src = GitSource::new("https://github.com/org/repo.git", rev, "apps");
            assert!(
                matches!(
                    src.validate(RepoUrlPolicy::Production),
                    Err(RepoError::InvalidSource { .. })
                ),
                "expected InvalidSource for revision {rev:?}"
            );
        }

        let bad_paths = [
            "/etc/kubernetes",
            "\\windows\\system32",
            "apps\\prod",
            "C:\\repo\\manifests",
            "C:manifests",
            "..",
            "../secrets",
            "a/../../b",
            "a\\..\\b",
            "apps\0/prod",
            "apps\nprod",
        ];
        for path in bad_paths {
            let src = GitSource::new("https://github.com/org/repo.git", "main", path);
            assert!(
                matches!(
                    src.validate(RepoUrlPolicy::Production),
                    Err(RepoError::InvalidSource { .. })
                ),
                "expected InvalidSource for path {path:?}"
            );
        }
    }

    #[test]
    fn validate_commit_sha_enforces_40_lowercase_hex() {
        let valid = "0123456789abcdef0123456789abcdef01234567";
        assert!(validate_commit_sha(valid).is_ok());

        let invalid = [
            "",
            "0123456789abcdef0123456789abcdef0123456", // 39 chars
            "0123456789abcdef0123456789abcdef012345678", // 41 chars
            "0123456789ABCDEF0123456789abcdef01234567", // uppercase
            "0123456789abcdef0123456789abcdef0123456g", // non-hex
            "main",
        ];
        for sha in invalid {
            assert!(
                matches!(
                    validate_commit_sha(sha),
                    Err(RepoError::InvalidRevision { .. })
                ),
                "expected InvalidRevision for {sha:?}"
            );
        }
    }
}
