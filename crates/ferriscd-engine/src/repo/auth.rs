//! Authentication material and transport hardening for `gix`-backed Git access.
//!
//! This module bridges [`RepoCredentials`] (a FerrisCD domain type) onto the two
//! authentication mechanisms `gix` actually supports:
//!
//! * **HTTPS** — credentials are supplied exclusively through the
//!   [`Connection::with_credentials()`][gix::remote::Connection::with_credentials] callback.
//!   `gix`'s HTTP transport only implements HTTP **Basic** authentication
//!   (`Authorization: Basic base64(user:password)`), so a bearer/personal-access token is
//!   mapped to `username = token`, `password = ""`, which is exactly equivalent to the
//!   `https://<token>@host/...` form GitHub/GitLab/Bitbucket support. Tokens are never placed
//!   in the clone URL, the in-memory `.git/config`, or any log/error message.
//!
//! * **SSH** — `gix` shells out to an `ssh` program. We write the private key and the
//!   `known_hosts` file into a private `0700` scratch directory as `0600` files, then set
//!   `core.sshCommand` (the configuration equivalent of the `GIT_SSH_COMMAND` environment
//!   variable) to a strictly-quoted command that pins the identity and enforces host key
//!   verification. [`TempKeyGuard`] overwrites the key with zeros and deletes the scratch
//!   directory on drop.
//!
//! ## Security notes
//!
//! * Passphrase-protected keys are rejected up-front: `gix` spawns `ssh` non-interactively
//!   (`BatchMode=yes`), so an encrypted key would either fail obscurely or hang until the
//!   operation timeout. Users should supply an unencrypted deploy key (scoped to a single
//!   repository) or rely on an `ssh-agent` that is already reachable from `ssh`.
//! * A missing `known_hosts` entry is a hard, terminal error
//!   ([`RepoError::HostKeyVerificationFailed`]) because accepting an unknown host key defeats
//!   MITM protection: the generated command pins `StrictHostKeyChecking=yes`.
//! * [`AuthContext::new`] accepts an explicit `allow_missing_known_hosts` flag. It is **insecure
//!   and intended for tests / trusted development environments only**: when enabled, a missing
//!   (or whitespace-only) `known_hosts` is accepted *and* the generated command switches to
//!   `StrictHostKeyChecking=accept-new` (trust-on-first-use) so the connection can actually
//!   proceed against a host that is not yet known. `UserKnownHostsFile=<scratch>/known_hosts`
//!   and `BatchMode=yes` are still applied, so nothing is read from or written to the
//!   operator's real `~/.ssh` files.
//! * [`AuthContext`] retains no private-key material: the PEM is written to the `0600` scratch
//!   file and its heap buffer is zero-filled before it is dropped. The credential callback only
//!   ever clones HTTP [`Account`][gix::sec::identity::Account] material; SSH operations return
//!   `Ok(None)`.
//! * No type in this module prints secret material from `Debug`, `Display`, or error paths.

use std::fmt;
use std::fs;
use std::hint::black_box;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::error::RepoError;
use super::types::RepoCredentials;

/// SSH program used when the client configuration does not override it.
const DEFAULT_SSH_PROGRAM: &str = "ssh";

/// Prefix of the private scratch directory that holds the ephemeral SSH key material.
const SSH_SCRATCH_PREFIX: &str = "ferriscd-ssh-";

/// File name of the ephemeral private key inside the scratch directory.
const SSH_KEY_FILE_NAME: &str = "ferriscd-deploy-key";

/// File name of the `known_hosts` copy inside the scratch directory.
const KNOWN_HOSTS_FILE_NAME: &str = "known_hosts";

/// Message returned when a passphrase-protected key is supplied.
const PASSPHRASE_UNSUPPORTED: &str =
    "passphrase-protected SSH keys are not supported; use an unencrypted key or ssh-agent";

/// Forces `gix` to treat the generated command as an OpenSSH command line.
const SSH_VARIANT_OVERRIDE: &str = "ssh.variant=ssh";

/// `ssh` option used for the production (default) host key policy.
const STRICT_HOST_KEY_CHECKING: &str = "StrictHostKeyChecking=yes";

/// `ssh` option used when `allow_missing_known_hosts` is enabled (trust-on-first-use).
const ACCEPT_NEW_HOST_KEY_CHECKING: &str = "StrictHostKeyChecking=accept-new";

/// Placeholder host used when the URL carries no host component.
const UNKNOWN_HOST: &str = "[unknown]";

/// `protocol`/`host` pair the credentials callback was provisioned for.
///
/// `gix` hands the callback a [`Context`][gix::credentials::protocol::Context] describing the
/// request it is currently serving; credentials are only released when that request maps onto
/// this endpoint (defense-in-depth against a callback being reused for another remote).
#[derive(Clone, Debug)]
struct Endpoint {
    /// Canonical scheme name (`"https"`, `"ssh"`, ...) of the repository URL.
    protocol: String,
    /// Host component of the repository URL, when it has one.
    host: Option<String>,
}

/// The single credential kind an operation is authorized to present.
enum AuthKind {
    /// No credentials at all (public HTTPS repositories, local fixtures).
    Anonymous,
    /// HTTP Basic identity derived from a token or a username/password pair.
    Http(gix::sec::identity::Account),
    /// SSH key material living in a [`TempKeyGuard`] scratch directory.
    Ssh {
        /// RAII owner of the ephemeral key/`known_hosts` files and the `ssh` command.
        guard: TempKeyGuard,
        /// Host the key was provisioned for (kept for redacted `Debug` output; the matching
        /// decision is made from `AuthContext::host`).
        host: String,
        /// Protocol the key was provisioned for (kept for redacted `Debug` output; the matching
        /// decision is made from `AuthContext::protocol`).
        protocol: String,
    },
}

impl fmt::Debug for AuthKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => f.write_str("AuthKind::Anonymous"),
            Self::Http(_) => f
                .debug_struct("AuthKind::Http")
                .field("account", &"[REDACTED]")
                .finish(),
            Self::Ssh {
                guard,
                host,
                protocol,
            } => f
                .debug_struct("AuthKind::Ssh")
                .field("private_key", &"[REDACTED]")
                .field("host", host)
                .field("protocol", protocol)
                .field("guard", guard)
                .finish(),
        }
    }
}

/// Owned, per-operation authentication context.
///
/// One instance is built at the start of every blocking `gix` operation (so all secret file
/// I/O happens on the blocking pool) and lives for the duration of that operation. It holds no
/// copy of the private-key PEM or of the `known_hosts` body: those exist only in the `0600`
/// scratch files (and, transiently, in a zeroized heap buffer while being written).
pub(crate) struct AuthContext {
    kind: AuthKind,
    protocol: String,
    host: Option<String>,
}

impl AuthContext {
    /// Builds an authentication context for `url` from `creds`.
    ///
    /// Validates that the credential kind is compatible with the URL scheme, rejects
    /// passphrase-protected keys, and enforces the `known_hosts` requirement for SSH.
    ///
    /// `allow_missing_known_hosts` is **insecure and reserved for tests / trusted development
    /// environments**. With the default `false`, a missing or whitespace-only `known_hosts` is a
    /// terminal [`RepoError::HostKeyVerificationFailed`] and the generated command pins
    /// `StrictHostKeyChecking=yes`. With `true`, the missing entry is tolerated *and* the command
    /// uses `StrictHostKeyChecking=accept-new` (trust-on-first-use) so the connection can
    /// proceed; `UserKnownHostsFile=<scratch>/known_hosts` and `BatchMode=yes` still apply, so
    /// the operator's real `~/.ssh/known_hosts` is neither read nor written.
    pub(crate) fn new(
        creds: &RepoCredentials,
        url: &gix::Url,
        allow_missing_known_hosts: bool,
        ssh_program: Option<&Path>,
    ) -> Result<Self, RepoError> {
        validate_credentials_for_url(creds, url)?;

        let protocol = url.scheme.as_str().to_owned();
        let host = url.host().map(ToOwned::to_owned);

        let kind = match creds {
            RepoCredentials::SshKey {
                private_key_pem,
                passphrase,
                known_hosts,
            } => {
                if passphrase.is_some() {
                    return Err(RepoError::AuthFailed {
                        reason: PASSPHRASE_UNSUPPORTED.to_owned(),
                    });
                }
                let known_hosts = known_hosts.as_deref().filter(|kh| !kh.trim().is_empty());
                if known_hosts.is_none() && !allow_missing_known_hosts {
                    return Err(RepoError::HostKeyVerificationFailed {
                        host: ssh_host(url),
                        reason:
                            "an explicit known_hosts entry is required for strict SSH host key \
                                 verification"
                                .to_owned(),
                    });
                }
                AuthKind::Ssh {
                    guard: TempKeyGuard::create(
                        private_key_pem,
                        known_hosts,
                        ssh_program,
                        allow_missing_known_hosts,
                    )?,
                    host: host.clone().unwrap_or_else(|| UNKNOWN_HOST.to_owned()),
                    protocol: protocol.clone(),
                }
            }
            RepoCredentials::Anonymous => AuthKind::Anonymous,
            // Only the non-secret-free HTTP identity is retained; the PEM/known_hosts body of an
            // SSH credential never survives into this context.
            RepoCredentials::HttpToken { token } => AuthKind::Http(gix::sec::identity::Account {
                username: token.clone(),
                password: String::new(),
                oauth_refresh_token: None,
            }),
            RepoCredentials::HttpBasic { username, password } => {
                AuthKind::Http(gix::sec::identity::Account {
                    username: username.clone(),
                    password: password.clone(),
                    oauth_refresh_token: None,
                })
            }
        };

        Ok(Self {
            kind,
            protocol,
            host,
        })
    }

    /// Returns the `gix` credentials callback for this context.
    ///
    /// Only HTTP [`Account`][gix::sec::identity::Account] material is cloned into the closure so
    /// the returned callback is `'static`; SSH and anonymous contexts clone nothing secret and
    /// always answer `Ok(None)`. `Store`/`Erase` actions (credential-helper caching) are also
    /// acknowledged with `Ok(None)` because FerrisCD never persists secrets.
    pub(crate) fn credentials_callback(
        &self,
    ) -> impl FnMut(
        gix::credentials::helper::Action,
    ) -> gix::Result<Option<gix::credentials::protocol::Outcome>>
    + 'static {
        let account = match &self.kind {
            AuthKind::Http(account) => Some(account.clone()),
            AuthKind::Anonymous | AuthKind::Ssh { .. } => None,
        };
        let endpoint = Endpoint {
            protocol: self.protocol.clone(),
            host: self.host.clone(),
        };
        move |action| Ok(outcome_for(account.as_ref(), &endpoint, action))
    }

    /// Configuration overrides that must be applied to every isolated repository created for
    /// this operation.
    ///
    /// For SSH key credentials this is `core.sshCommand=<quoted command>` plus
    /// `ssh.variant=ssh`. `core.sshCommand` is the exact configuration equivalent of exporting
    /// `GIT_SSH_COMMAND`: `gix` resolves it (with `GIT_SSH_COMMAND` as its documented
    /// environment override) in [`gix::Repository::ssh_connect_options()`] when a remote
    /// transport is built. A per-repository config override keeps the operation thread-safe
    /// (no `std::env::set_var`, which is racy and `unsafe` in Edition 2024) and confines the
    /// key path to that repository's in-memory configuration — it never reaches
    /// `.git/config` on disk or the process environment.
    ///
    /// `ssh.variant=ssh` is required because the generated command is an OpenSSH-style command
    /// line (`-i`, `-o ...`); without it `gix` classifies the multi-word command as the
    /// `Simple` variant, which rejects explicit SSH ports and performs an extra `-G` probe.
    ///
    /// **Environment sensitivity:** `gix` applies process-environment overrides *after* these
    /// API-level overrides, so a pre-existing `GIT_SSH_VARIANT` in the environment wins over the
    /// `ssh.variant=ssh` pin (and `GIT_SSH_COMMAND` wins over `core.sshCommand`). FerrisCD does
    /// not mutate process environment to avoid racy, `unsafe` writes; operators should not set
    /// `GIT_SSH_VARIANT`/`GIT_SSH_COMMAND` for the controller process.
    pub(crate) fn config_overrides(&self) -> Vec<gix::bstr::BString> {
        match &self.kind {
            AuthKind::Ssh { guard, .. } => vec![
                gix::bstr::BString::from(SSH_VARIANT_OVERRIDE),
                guard.config_override(),
            ],
            AuthKind::Anonymous | AuthKind::Http(_) => Vec::new(),
        }
    }

    /// Returns the generated SSH command, if SSH key credentials are in use.
    #[cfg(test)]
    pub(crate) fn ssh_command(&self) -> Option<&str> {
        match &self.kind {
            AuthKind::Ssh { guard, .. } => Some(guard.command.as_str()),
            AuthKind::Anonymous | AuthKind::Http(_) => None,
        }
    }

    /// Returns the ephemeral private key path, if SSH key credentials are in use.
    #[cfg(test)]
    pub(crate) fn temp_key_path(&self) -> Option<&Path> {
        match &self.kind {
            AuthKind::Ssh { guard, .. } => Some(guard.key_path.as_path()),
            AuthKind::Anonymous | AuthKind::Http(_) => None,
        }
    }
}

impl fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthContext")
            // `AuthKind`'s own `Debug` replaces every secret with `[REDACTED]`.
            .field("auth", &self.kind)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .finish()
    }
}

/// RAII guard owning the private scratch directory for SSH key material.
///
/// * The directory is a `tempfile::TempDir` (created `0700`) with prefix
///   [`SSH_SCRATCH_PREFIX`].
/// * The private key and the `known_hosts` copy are written as `0600` files.
/// * `Drop` overwrites the key file with zeros and then removes the whole directory tree.
pub(crate) struct TempKeyGuard {
    dir: TempDir,
    key_path: PathBuf,
    known_hosts_path: PathBuf,
    command: String,
}

impl TempKeyGuard {
    /// Materializes the key/`known_hosts` files and builds the hardened `ssh` command.
    ///
    /// `allow_missing_known_hosts` switches the command to `StrictHostKeyChecking=accept-new`
    /// (insecure; tests/dev only) instead of the default `StrictHostKeyChecking=yes`.
    fn create(
        private_key_pem: &str,
        known_hosts: Option<&str>,
        ssh_program: Option<&Path>,
        allow_missing_known_hosts: bool,
    ) -> Result<Self, RepoError> {
        let dir = tempfile::Builder::new()
            .prefix(SSH_SCRATCH_PREFIX)
            .tempdir()
            .map_err(|source| RepoError::Io {
                context: "creating private SSH scratch directory".to_owned(),
                source,
            })?;

        let key_path = dir.path().join(SSH_KEY_FILE_NAME);
        let known_hosts_path = dir.path().join(KNOWN_HOSTS_FILE_NAME);

        // OpenSSH requires a trailing newline on key files; tolerate either form on input. The
        // key lives in an owned buffer so it can be zero-filled as soon as it hit the disk,
        // whether or not the write succeeded.
        let mut key_body = private_key_pem.as_bytes().to_vec();
        if !key_body.ends_with(b"\n") {
            key_body.push(b'\n');
        }
        let written = write_private_file(&key_path, &key_body);
        zeroize(&mut key_body);
        written?;

        // `known_hosts` is public data, but `ssh` still wants one entry per line.
        let mut known_hosts_body = known_hosts.unwrap_or("").to_owned();
        if !known_hosts_body.is_empty() && !known_hosts_body.ends_with('\n') {
            known_hosts_body.push('\n');
        }
        write_private_file(&known_hosts_path, known_hosts_body.as_bytes())?;

        let program = match ssh_program {
            Some(path) => path.to_str().ok_or_else(|| RepoError::AuthFailed {
                reason: "configured ssh program path is not valid UTF-8".to_owned(),
            })?,
            None => DEFAULT_SSH_PROGRAM,
        };
        let command = build_ssh_command(
            program,
            &key_path,
            &known_hosts_path,
            allow_missing_known_hosts,
        )?;

        Ok(Self {
            dir,
            key_path,
            known_hosts_path,
            command,
        })
    }

    /// Returns the `core.sshCommand=<command>` configuration override.
    fn config_override(&self) -> gix::bstr::BString {
        format!("core.sshCommand={}", self.command).into()
    }
}

impl fmt::Debug for TempKeyGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only paths and flags: never the key body, never the command (it embeds the key path
        // and could be confused with secret material when copied into logs wholesale).
        f.debug_struct("TempKeyGuard")
            .field("scratch_dir", &self.dir.path())
            .field("key_path", &self.key_path)
            .field("known_hosts_path", &self.known_hosts_path)
            .finish()
    }
}

impl Drop for TempKeyGuard {
    fn drop(&mut self) {
        // Best-effort zeroization: overwrite the key in place before `TempDir` removes the tree.
        if let Ok(metadata) = fs::metadata(&self.key_path)
            && let Ok(len) = usize::try_from(metadata.len())
            && let Ok(mut file) = fs::OpenOptions::new().write(true).open(&self.key_path)
        {
            let mut zeros = vec![0u8; len];
            let _ = file.write_all(&zeros);
            let _ = file.flush();
            let _ = file.sync_all();
            zeroize(&mut zeros);
        }
        // Dropping `self.dir` (a `TempDir`) recursively deletes key + known_hosts.
    }
}

/// Best-effort manual zeroization of a heap buffer that held secret material.
///
/// No `zeroize` dependency is pulled in: `fill(0)` followed by a [`black_box`] read keeps the
/// store from being optimized away as a dead write before the allocation is freed.
fn zeroize(buf: &mut [u8]) {
    buf.fill(0);
    black_box(buf);
}

/// Rejects credential kinds that cannot be used with `url`'s scheme.
///
/// All rejections are terminal (`RepoError::is_retryable() == false`) so a controller does not
/// hot-loop on a misconfiguration.
pub(crate) fn validate_credentials_for_url(
    creds: &RepoCredentials,
    url: &gix::Url,
) -> Result<(), RepoError> {
    let is_ssh = url.scheme == gix::url::Scheme::Ssh;
    let is_https = url.scheme == gix::url::Scheme::Https;

    match creds {
        RepoCredentials::Anonymous if is_ssh => Err(RepoError::HostKeyVerificationFailed {
            host: ssh_host(url),
            reason: "SSH repositories require SSH key credentials plus a known_hosts entry"
                .to_owned(),
        }),
        RepoCredentials::Anonymous => Ok(()),
        RepoCredentials::SshKey { .. } if !is_ssh => Err(RepoError::AuthFailed {
            reason: "SSH key credentials can only be used with 'ssh://' or SCP-style SSH \
                     repository URLs"
                .to_owned(),
        }),
        RepoCredentials::SshKey { .. } => Ok(()),
        RepoCredentials::HttpToken { .. } | RepoCredentials::HttpBasic { .. } if !is_https => {
            Err(RepoError::AuthFailed {
                reason: "HTTPS credentials can only be used with 'https://' repository URLs"
                    .to_owned(),
            })
        }
        RepoCredentials::HttpToken { .. } | RepoCredentials::HttpBasic { .. } => Ok(()),
    }
}

/// Builds the identity outcome for a credential-helper `action`.
///
/// Returns `None` for everything but `Get`, for contexts that are not authorized to receive
/// credentials, and for credential kinds that the HTTP transport cannot use. `gix`'s HTTP
/// transport implements Basic auth only, hence the token mapping documented on this module.
fn outcome_for(
    account: Option<&gix::sec::identity::Account>,
    endpoint: &Endpoint,
    action: gix::credentials::helper::Action,
) -> Option<gix::credentials::protocol::Outcome> {
    let gix::credentials::helper::Action::Get(ctx) = action else {
        return None;
    };
    let account = account?;
    if !endpoint_matches(endpoint, &ctx) {
        return None;
    }
    Some(gix::credentials::protocol::Outcome {
        identity: account.clone(),
        next: gix::credentials::helper::NextAction::from(ctx),
    })
}

/// Returns whether the request `ctx` describes the endpoint this context was provisioned for.
///
/// Only fields `gix` actually populated are compared; a request that names a different
/// protocol or host than the expected one is refused (defense-in-depth: the callback is bound to
/// exactly one operation and must never release credentials to another remote).
fn endpoint_matches(endpoint: &Endpoint, ctx: &gix::credentials::protocol::Context) -> bool {
    if let Some(protocol) = ctx.protocol.as_deref()
        && !protocol.eq_ignore_ascii_case(&endpoint.protocol)
    {
        return false;
    }
    match (ctx.host.as_deref(), endpoint.host.as_deref()) {
        (Some(actual), Some(expected)) => host_matches(expected, actual),
        // The request names a host this context knows nothing about: refuse.
        (Some(_), None) => false,
        (None, _) => true,
    }
}

/// Returns whether `actual` (which may carry a `:port` suffix) names the host `expected`.
fn host_matches(expected: &str, actual: &str) -> bool {
    if expected.eq_ignore_ascii_case(actual) {
        return true;
    }
    actual.rsplit_once(':').is_some_and(|(host, port)| {
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && host.eq_ignore_ascii_case(expected)
    })
}

/// Shell-quotes `arg` for a POSIX `sh -c` command line.
///
/// Every argument is wrapped in single quotes and an embedded `'` is rendered as `'\''`.
/// NUL, `\n`, and `\r` would be silently mangled by `sh` (or truncate the value) and are
/// rejected outright.
pub(crate) fn shell_quote(arg: &str) -> Result<String, RepoError> {
    if arg.contains(['\0', '\n', '\r']) {
        return Err(RepoError::AuthFailed {
            reason: "ssh command arguments must not contain NUL or newline characters".to_owned(),
        });
    }
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    Ok(quoted)
}

/// Builds the hardened `ssh` command string used for `core.sshCommand`.
///
/// `-i <key>` + `IdentitiesOnly=yes` pins the exact deploy key, `UserKnownHostsFile=<scratch
/// copy>` keeps host key lookups inside the scratch directory, and `BatchMode=yes` guarantees
/// `ssh` can never block on an interactive prompt (the operation would otherwise hang instead of
/// failing). `StrictHostKeyChecking` is `yes` by default; it is downgraded to `accept-new`
/// (trust-on-first-use) only when `allow_missing_known_hosts` is set, which is insecure and
/// reserved for tests / trusted development environments.
pub(crate) fn build_ssh_command(
    program: &str,
    key_path: &Path,
    known_hosts_path: &Path,
    allow_missing_known_hosts: bool,
) -> Result<String, RepoError> {
    let key = path_str(key_path)?;
    let known_hosts = path_str(known_hosts_path)?;
    let host_key_checking = if allow_missing_known_hosts {
        ACCEPT_NEW_HOST_KEY_CHECKING
    } else {
        STRICT_HOST_KEY_CHECKING
    };
    Ok(format!(
        "{} -i {} -o IdentitiesOnly=yes -o {} -o UserKnownHostsFile={} -o BatchMode=yes",
        shell_quote(program)?,
        shell_quote(key)?,
        host_key_checking,
        shell_quote(known_hosts)?
    ))
}

fn path_str(path: &Path) -> Result<&str, RepoError> {
    path.to_str().ok_or_else(|| RepoError::AuthFailed {
        reason: "ssh scratch path is not valid UTF-8".to_owned(),
    })
}

fn ssh_host(url: &gix::Url) -> String {
    url.host().unwrap_or(UNKNOWN_HOST).to_owned()
}

/// Writes `contents` to a freshly created file, restricting it to the owner (`0600`).
fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), RepoError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| RepoError::Io {
        context: "creating private SSH scratch file".to_owned(),
        source,
    })?;
    file.write_all(contents).map_err(|source| RepoError::Io {
        context: "writing private SSH scratch file".to_owned(),
        source,
    })?;
    file.flush().map_err(|source| RepoError::Io {
        context: "flushing private SSH scratch file".to_owned(),
        source,
    })?;
    Ok(())
}

// The test module materializes `0600` files and inspects them through `PermissionsExt`, so it is
// Unix-only. `#![cfg(unix)]` is an inner attribute, which clippy flags when combined with the
// outer `#[cfg(test)]`; the allow is scoped to this one module.
#[cfg(test)]
#[allow(clippy::mixed_attributes_style)]
mod tests {
    #![cfg(unix)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const KEY_BODY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_KEY_BODY\n-----END OPENSSH PRIVATE KEY-----";
    const KNOWN_HOSTS: &str = "";
    const KNOWN_HOSTS_BODY: &str = "example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISECRET";

    fn ssh_url(raw: &str) -> gix::Url {
        gix::url::parse(raw.as_bytes()).expect("valid ssh url")
    }

    fn ssh_creds(passphrase: Option<&str>, known_hosts: Option<&str>) -> RepoCredentials {
        RepoCredentials::SshKey {
            private_key_pem: KEY_BODY.to_owned(),
            passphrase: passphrase.map(ToOwned::to_owned),
            known_hosts: known_hosts.map(ToOwned::to_owned),
        }
    }

    /// `Get` action built the way [`Action::get_for_url`] does: only `url` is populated.
    fn get_action(url: &str) -> gix::credentials::helper::Action {
        gix::credentials::helper::Action::get_for_url(url)
    }

    /// `Get` action built the way `gix`'s HTTP transport does: `protocol`/`host` are populated.
    fn get_for(protocol: &str, host: &str) -> gix::credentials::helper::Action {
        gix::credentials::helper::Action::Get(gix::credentials::protocol::Context {
            protocol: Some(protocol.to_owned()),
            host: Some(host.to_owned()),
            ..Default::default()
        })
    }

    #[test]
    fn temp_key_guard_writes_0600_files_and_removes_them_on_drop() {
        let url = ssh_url("ssh://git@example.invalid/org/repo.git");
        let creds = ssh_creds(None, Some(KNOWN_HOSTS_BODY));
        let auth = AuthContext::new(&creds, &url, false, None).expect("auth context");

        let key_path = auth.temp_key_path().expect("ssh key path").to_path_buf();
        let scratch_dir = key_path.parent().expect("scratch dir").to_path_buf();
        let known_hosts_path = scratch_dir.join(KNOWN_HOSTS_FILE_NAME);

        assert!(key_path.is_file(), "private key must exist");
        assert!(known_hosts_path.is_file(), "known_hosts must exist");

        let key_mode = fs::metadata(&key_path)
            .expect("stat key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            key_mode, 0o600,
            "private key must be 0600, got {key_mode:o}"
        );
        let kh_mode = fs::metadata(&known_hosts_path)
            .expect("stat known_hosts")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            kh_mode, 0o600,
            "known_hosts copy must be 0600, got {kh_mode:o}"
        );

        // Key and `known_hosts` bodies are newline-normalized on write.
        let key_body = fs::read_to_string(&key_path).expect("read key");
        assert_eq!(key_body, format!("{KEY_BODY}\n"));
        assert_eq!(
            fs::read_to_string(&known_hosts_path).expect("read known_hosts"),
            format!("{KNOWN_HOSTS_BODY}\n")
        );

        let command = auth.ssh_command().expect("ssh command").to_owned();
        for needle in [
            "-i ",
            "IdentitiesOnly=yes",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=",
            "BatchMode=yes",
            scratch_dir.to_str().expect("utf8 scratch dir"),
        ] {
            assert!(
                command.contains(needle),
                "ssh command missing {needle}: {command}"
            );
        }
        assert!(
            !command.contains("accept-new"),
            "strict host key checking must be the default: {command}"
        );

        drop(auth);
        assert!(
            !scratch_dir.exists(),
            "scratch dir must be deleted on drop: {}",
            scratch_dir.display()
        );
        assert!(!key_path.exists(), "ephemeral key must be deleted on drop");
        assert!(!known_hosts_path.exists());
    }

    #[test]
    fn temp_key_guard_uses_configured_ssh_program_and_quotes_it() {
        let url = ssh_url("ssh://git@example.invalid/org/repo.git");
        let creds = ssh_creds(None, Some(KNOWN_HOSTS_BODY));
        let program = PathBuf::from("/opt/my tools/fake ssh");
        let auth =
            AuthContext::new(&creds, &url, false, Some(program.as_path())).expect("auth context");
        let command = auth.ssh_command().expect("ssh command").to_owned();
        assert!(
            command.starts_with("'/opt/my tools/fake ssh' -i '"),
            "ssh program must be single-quoted: {command}"
        );
    }

    #[test]
    fn shell_quote_handles_spaces_quotes_dollars_and_semicolons() {
        let cases = [
            ("/tmp/plain", "'/tmp/plain'"),
            ("/tmp/with space/key", "'/tmp/with space/key'"),
            ("/tmp/it's here", "'/tmp/it'\\''s here'"),
            ("/tmp/$HOME/key", "'/tmp/$HOME/key'"),
            ("/tmp/a;rm -rf /", "'/tmp/a;rm -rf /'"),
            ("/tmp/`id`", "'/tmp/`id`'"),
            ("", "''"),
        ];
        for (input, expected) in cases {
            let quoted = shell_quote(input).expect("quotable");
            assert_eq!(quoted, expected, "unexpected quoting for {input:?}");
            // A single leading and trailing quote, with every embedded quote escaped.
            assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
            assert!(!quoted.contains('\u{0}'));
        }

        for rejected in ["/tmp/a\0b", "/tmp/a\nb", "/tmp/a\rb"] {
            let err = shell_quote(rejected).expect_err("control characters must be rejected");
            assert!(matches!(err, RepoError::AuthFailed { .. }));
            assert!(!err.is_retryable());
        }
    }

    #[test]
    fn build_ssh_command_quotes_every_path() {
        let key = PathBuf::from("/tmp/key with space/id");
        let known_hosts = PathBuf::from("/tmp/kh/it's");
        let command = build_ssh_command("ssh", &key, &known_hosts, false).expect("command");
        assert_eq!(
            command,
            "'ssh' -i '/tmp/key with space/id' -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes \
             -o UserKnownHostsFile='/tmp/kh/it'\\''s' -o BatchMode=yes"
        );

        let insecure = build_ssh_command("ssh", &key, &known_hosts, true).expect("command");
        assert!(
            insecure.contains("-o StrictHostKeyChecking=accept-new "),
            "the insecure dev flag must downgrade host key checking: {insecure}"
        );
        assert!(
            !insecure.contains("StrictHostKeyChecking=yes"),
            "{insecure}"
        );
    }

    #[test]
    fn missing_known_hosts_requires_the_insecure_opt_in_flag() {
        let url = ssh_url("ssh://git@example.invalid/org/repo.git");

        for known_hosts in [None, Some("  ")] {
            let creds = ssh_creds(None, known_hosts);
            let err = AuthContext::new(&creds, &url, false, None)
                .expect_err("missing known_hosts must be rejected");
            match &err {
                RepoError::HostKeyVerificationFailed { host, .. } => {
                    assert_eq!(host, "example.invalid");
                }
                other => panic!("expected HostKeyVerificationFailed, got {other:?}"),
            }
            assert!(!err.is_retryable());

            // With the flag on the context is built without a `known_hosts` entry at all...
            let auth = AuthContext::new(&creds, &url, true, None)
                .expect("insecure dev flag must allow a missing known_hosts");
            let command = auth.ssh_command().expect("ssh command").to_owned();
            assert!(
                command.contains("StrictHostKeyChecking=accept-new"),
                "the insecure dev flag must use trust-on-first-use: {command}"
            );
            assert!(
                command.contains("UserKnownHostsFile="),
                "the scratch known_hosts must still be pinned: {command}"
            );
            assert!(
                command.contains("BatchMode=yes"),
                "ssh must stay non-interactive: {command}"
            );
            let key_path = auth.temp_key_path().expect("key path").to_path_buf();
            let scratch_dir = key_path.parent().expect("scratch dir").to_path_buf();
            assert_eq!(
                fs::read_to_string(scratch_dir.join(KNOWN_HOSTS_FILE_NAME))
                    .expect("read empty known_hosts"),
                KNOWN_HOSTS
            );
        }
    }

    #[test]
    fn panic_while_auth_context_is_live_still_removes_the_scratch_dir() {
        // The panic message is deliberately secret-free: the default panic hook prints it to
        // stderr, and the guard's Drop runs during unwinding.
        let url = ssh_url("ssh://git@example.invalid/org/repo.git");
        let creds = ssh_creds(None, Some(KNOWN_HOSTS_BODY));

        let mut scratch_dir: Option<PathBuf> = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let auth = AuthContext::new(&creds, &url, false, None).expect("auth context");
            scratch_dir = auth
                .temp_key_path()
                .expect("ssh key path")
                .parent()
                .map(Path::to_path_buf);
            assert!(scratch_dir.as_ref().expect("scratch dir").is_dir());
            panic!("intentional panic: unwind past a live auth context");
        }));

        assert!(outcome.is_err(), "the test body must have panicked");
        let scratch_dir = scratch_dir.expect("scratch dir must have been materialized");
        assert!(
            scratch_dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(SSH_SCRATCH_PREFIX)),
            "unexpected scratch dir: {}",
            scratch_dir.display()
        );
        assert!(
            !scratch_dir.exists(),
            "unwinding must still delete the ephemeral key directory: {}",
            scratch_dir.display()
        );
    }

    #[test]
    fn passphrase_protected_keys_are_rejected_with_a_clear_message() {
        let url = ssh_url("ssh://git@example.invalid/org/repo.git");
        let creds = ssh_creds(Some("super-secret-passphrase"), Some(KNOWN_HOSTS_BODY));
        let err = AuthContext::new(&creds, &url, true, None).expect_err("passphrase must fail");
        let text = format!("{err} {err:?}");
        assert!(matches!(err, RepoError::AuthFailed { .. }));
        assert!(!err.is_retryable());
        assert!(text.contains("passphrase-protected SSH keys are not supported"));
        assert!(!text.contains("super-secret-passphrase"));
    }

    #[test]
    fn credential_callback_maps_http_token_and_basic_identities() {
        let url = ssh_url("https://example.invalid/org/repo.git");
        assert_eq!(url.scheme, gix::url::Scheme::Https);

        let token = "ghp_super_secret_token";
        let auth = AuthContext::new(
            &RepoCredentials::HttpToken {
                token: token.to_owned(),
            },
            &url,
            false,
            None,
        )
        .expect("token context");
        let mut callback = auth.credentials_callback();
        let outcome = callback(get_action("https://example.invalid/org/repo.git"))
            .expect("callback must not fail")
            .expect("token credentials must be returned");
        assert_eq!(outcome.identity.username, token);
        assert_eq!(outcome.identity.password, "");
        assert!(outcome.identity.oauth_refresh_token.is_none());

        let auth = AuthContext::new(
            &RepoCredentials::HttpBasic {
                username: "ci-bot".to_owned(),
                password: "hunter2".to_owned(),
            },
            &url,
            false,
            None,
        )
        .expect("basic context");
        let mut callback = auth.credentials_callback();
        let outcome = callback(get_action("https://example.invalid/org/repo.git"))
            .expect("callback must not fail")
            .expect("basic credentials must be returned");
        assert_eq!(outcome.identity.username, "ci-bot");
        assert_eq!(outcome.identity.password, "hunter2");

        let mut callback = auth.credentials_callback();
        let payload: gix::bstr::BString = "protocol=https\nhost=example.invalid\n".into();
        assert!(
            callback(gix::credentials::helper::Action::Store(payload.clone()))
                .expect("store must not fail")
                .is_none()
        );
        assert!(
            callback(gix::credentials::helper::Action::Erase(payload))
                .expect("erase must not fail")
                .is_none()
        );
        assert!(auth.config_overrides().is_empty());
    }

    #[test]
    fn credential_callback_refuses_mismatched_protocol_or_host() {
        let url = ssh_url("https://example.invalid/org/repo.git");
        let auth = AuthContext::new(
            &RepoCredentials::HttpToken {
                token: "ghp_secret".to_owned(),
            },
            &url,
            false,
            None,
        )
        .expect("token context");

        // Matching endpoint (case-insensitive, with and without an explicit port) keeps working.
        for (protocol, host) in [
            ("https", "example.invalid"),
            ("HTTPS", "EXAMPLE.invalid"),
            ("https", "example.invalid:8443"),
        ] {
            let mut callback = auth.credentials_callback();
            assert!(
                callback(get_for(protocol, host))
                    .expect("callback must not fail")
                    .is_some(),
                "credentials must be released for {protocol}://{host}"
            );
        }

        // A different protocol or host must never receive the identity.
        for (protocol, host) in [
            ("http", "example.invalid"),
            ("ssh", "example.invalid"),
            ("https", "evil.invalid"),
            ("https", "example.invalid.evil.invalid"),
        ] {
            let mut callback = auth.credentials_callback();
            assert!(
                callback(get_for(protocol, host))
                    .expect("callback must not fail")
                    .is_none(),
                "credentials must not be released for {protocol}://{host}"
            );
        }

        // `Action::get_for_url` only populates `url` (`protocol`/`host` stay `None`), so the
        // hardened mapping tests above keep observing credentials exactly as before.
        let mut callback = auth.credentials_callback();
        assert!(
            callback(get_action("https://example.invalid/org/repo.git"))
                .expect("callback must not fail")
                .is_some()
        );
    }

    #[test]
    fn anonymous_and_ssh_credentials_never_yield_http_identities() {
        let https = ssh_url("https://example.invalid/org/repo.git");
        let ssh = ssh_url("ssh://git@example.invalid/org/repo.git");
        let https_action = "https://example.invalid/org/repo.git";

        let anonymous = AuthContext::new(&RepoCredentials::Anonymous, &https, false, None)
            .expect("anonymous context");
        let mut callback = anonymous.credentials_callback();
        assert!(
            callback(get_action(https_action))
                .expect("callback must not fail")
                .is_none()
        );

        // An SSH context must never answer an HTTPS credential request either.
        let ssh_auth =
            AuthContext::new(&ssh_creds(None, Some(KNOWN_HOSTS_BODY)), &ssh, false, None)
                .expect("ssh context");
        let mut callback = ssh_auth.credentials_callback();
        assert!(
            callback(get_action(https_action))
                .expect("callback must not fail")
                .is_none()
        );

        // `Anonymous` over HTTPS is a legitimate (public repository) configuration.
        assert!(validate_credentials_for_url(&RepoCredentials::Anonymous, &https).is_ok());
    }

    #[test]
    fn credential_url_compatibility_is_enforced_as_terminal_errors() {
        let ssh = ssh_url("ssh://git@example.invalid/org/repo.git");
        let https = ssh_url("https://example.invalid/org/repo.git");
        let file = ssh_url("file:///tmp/repo");

        let http_token = RepoCredentials::HttpToken {
            token: "ghp_secret".to_owned(),
        };
        let basic = RepoCredentials::HttpBasic {
            username: "u".to_owned(),
            password: "p".to_owned(),
        };
        let ssh_key = ssh_creds(None, Some(KNOWN_HOSTS_BODY));

        for creds in [&http_token, &basic] {
            let err = AuthContext::new(creds, &ssh, true, None)
                .expect_err("HTTP credentials with an SSH URL must fail");
            assert!(matches!(err, RepoError::AuthFailed { .. }));
            assert!(!err.is_retryable());
            let err = AuthContext::new(creds, &file, true, None)
                .expect_err("HTTP credentials with a file URL must fail");
            assert!(matches!(err, RepoError::AuthFailed { .. }));
            assert!(!err.is_retryable());
        }

        for url in [&https, &file] {
            let err = AuthContext::new(&ssh_key, url, true, None)
                .expect_err("SSH key credentials with a non-SSH URL must fail");
            assert!(matches!(err, RepoError::AuthFailed { .. }));
            assert!(!err.is_retryable());
        }

        let anon_err = AuthContext::new(&RepoCredentials::Anonymous, &ssh, true, None)
            .expect_err("anonymous SSH must fail before spawning ssh");
        assert!(matches!(
            anon_err,
            RepoError::HostKeyVerificationFailed { .. }
        ));
        assert!(!anon_err.is_retryable());

        // HTTPS credentials over an HTTPS URL remain valid.
        for creds in [&http_token, &basic] {
            assert!(validate_credentials_for_url(creds, &https).is_ok());
        }
    }

    #[test]
    fn auth_context_debug_and_errors_never_leak_secrets() {
        let ssh_endpoint = ssh_url("ssh://git@example.invalid/org/repo.git");
        let creds = ssh_creds(None, Some(KNOWN_HOSTS_BODY));
        let auth = AuthContext::new(&creds, &ssh_endpoint, false, None).expect("ssh context");
        let debug = format!("{auth:?} {auth:#?}");
        assert!(!debug.contains("SECRET_KEY_BODY"));
        assert!(!debug.contains(KNOWN_HOSTS_BODY));
        assert!(debug.contains("[REDACTED]"));
        assert!(debug.contains("TempKeyGuard"));

        let https_url = ssh_url("https://example.invalid/org/repo.git");
        let token_secret = "ghp_super_secret_token_987654";
        let auth = AuthContext::new(
            &RepoCredentials::HttpToken {
                token: token_secret.to_owned(),
            },
            &https_url,
            false,
            None,
        )
        .expect("token context");
        let debug = format!("{auth:?} {auth:#?}");
        assert!(!debug.contains(token_secret));
        assert!(debug.contains("[REDACTED]"));

        let basic = RepoCredentials::HttpBasic {
            username: "ci-user-secret".to_owned(),
            password: "ci-pass-secret".to_owned(),
        };
        let auth = AuthContext::new(&basic, &https_url, false, None).expect("basic context");
        let debug = format!("{auth:?} {auth:#?}");
        assert!(!debug.contains("ci-user-secret"));
        assert!(!debug.contains("ci-pass-secret"));
        assert!(debug.contains("[REDACTED]"));

        let err = AuthContext::new(&creds, &https_url, false, None)
            .expect_err("ssh creds over https must fail");
        let text = format!("{err} {err:?}");
        assert!(!text.contains("SECRET_KEY_BODY"));
        assert!(!text.contains(KNOWN_HOSTS_BODY));
    }
}
