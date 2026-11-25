//! Kubernetes `Secret`-backed Git repository credentials (`T12.4`).
//!
//! An `Application` that clones a private repository needs an identity. FerrisCD keeps those
//! identities in `Secret`s that live **only in the control-plane namespace** (`ferriscd-system`
//! by default, i.e. the controller's `--namespace`) and that opt in with one label:
//!
//! ```yaml
//! apiVersion: v1
//! kind: Secret
//! metadata:
//!   name: repo-git-example-com
//!   namespace: ferriscd-system
//!   labels:
//!     ferriscd.io/secret-type: repository
//! stringData:
//!   url: https://git.example.com            # exact URL or longest-prefix template
//!   username: ferriscd-bot                  # optional
//!   password: <personal access token>       # or `token:` alone for a bearer token
//! ```
//!
//! ## Scope: never cluster-wide (trap guard for `T12.4`)
//!
//! [`SecretCredentialStore`] holds an `Api<Secret>` created with `Api::namespaced`, and every read
//! is one label-filtered **list inside that namespace**. It therefore can never observe a
//! `Secret` from another namespace — not because it filters, but because the request path is
//! `/api/v1/namespaces/<control-plane>/secrets`. The controller's `ClusterRole` consequently needs
//! `get`/`list`/`watch` on `secrets` **in one namespace only**, never a cluster-wide `Secret` read
//! (`deploy/README.md`). A `Secret` that a tenant creates in its own namespace is invisible here;
//! tenants cannot inject a credential the operator did not put in the control plane.
//!
//! Reads are scoped fetches on demand (one per reconcile that resolves a repository), not a
//! background cluster-wide informer — the same model as [`crate::project::ApiProjectSource`].
//!
//! ## The Secret data contract
//!
//! | Key | Required | Meaning |
//! |---|---|---|
//! | [`KEY_URL`] (`url`) | yes | repository URL, or a prefix of it (`https://git.example.com`) |
//! | [`KEY_USERNAME`] (`username`) | no | HTTPS basic-auth user |
//! | [`KEY_PASSWORD`] (`password`) | no | HTTPS basic-auth password **or**, without `username`, a bearer token |
//! | [`KEY_TOKEN`] (`token`) | no | HTTPS bearer / personal access token |
//! | [`KEY_SSH_PRIVATE_KEY`] (`sshPrivateKey`) | no | unencrypted SSH private key (PEM / OpenSSH) |
//! | [`KEY_KNOWN_HOSTS`] (`knownHosts`) | no | `known_hosts` entry pinning the SSH host key |
//!
//! `data` values are base64 on the wire and plain text once decoded (that is what
//! `k8s-openapi`'s `ByteString` gives us); `stringData` is accepted too, which is what makes a
//! fixture written by hand easy to read. Only one credential kind may be present: an ambiguous
//! `Secret` (both an SSH key and an HTTPS password, both `password` and `token`, an SSH key on an
//! `https://` url, …) is a terminal error naming the `Secret` and the offending keys, never a
//! silently chosen one.
//!
//! Only `https://` and `ssh://` templates are accepted: `http://` (plaintext) and every other
//! scheme is a terminal error rather than a credential that could never be used — FerrisCD's Git
//! layer rejects plaintext remotes and refuses to send credentials over them at all.
//!
//! ## Matching rules
//!
//! URLs are compared through [`normalize_repo_url`], which makes a match predictable:
//!
//! * the **whole normalized URL is lowercased, the path included** (DNS is case-insensitive, and
//!   Git hosting paths are conventionally case-insensitive too), so `HTTPS://Git.Example.com` and
//!   `https://git.example.com/Org/Repo` match `https://git.example.com/org/repo`. This is a
//!   deliberate, documented trade-off: on a self-hosted Git server that distinguishes
//!   `/Org/Repo` from `/org/repo`, one credential `Secret` covers both (they are treated as the
//!   same repository), which is the safe direction — it can never *widen* which credential is
//!   used beyond a host the operator already recorded;
//! * userinfo is dropped from **both** sides, so the SCP-style form Git users actually copy
//!   (`git@github.com:org/repo.git`) and `ssh://github.com/org/repo` are the same repository;
//! * one trailing `/`, any number of trailing slashes, and one trailing `.git` are removed;
//! * an exact match beats every prefix; among prefixes the **longest** one wins;
//! * a prefix only matches on a path-segment boundary, so `https://git.example.com/org` matches
//!   `https://git.example.com/org/repo` but **not** `https://git.example.com/organization/repo`
//!   and never `https://git.example.com.evil/repo` (host suffix confusion);
//! * a host-only template (`https://git.example.com`) matches every repository on that host —
//!   one `Secret` per Git server instead of one per repository.
//!
//! One unusable `Secret` fails **every** credentialed resolve until it is fixed, rather than being
//! skipped. Silently ignoring it would make "why did this `Application` stop authenticating?"
//! invisible: the observable symptom would be an anonymous clone that fails (or, worse, succeeds
//! against a now-public repository), instead of a `Ready=False` naming the `Secret` to repair.
//!
//! No match is **not** an error: the repository is cloned anonymously, which is the behaviour
//! before `T12.4` and the correct one for public repositories.
//!
//! ## Secret hygiene
//!
//! Nothing in this module prints a credential. [`CredentialTemplate`], [`SecretCredentialStore`],
//! and [`CredentialError`] redact the `Secret` payloads, and the repository URL always goes
//! through [`redact_repo_url`] before it reaches a `Debug`, `Display`, log line, or the
//! `Application`'s `/status` — a Git remote routinely embeds a personal access token, and a
//! `Secret`'s `url` key is a remote too.
//!
//! ## Kubernetes RBAC
//!
//! ```yaml
//! - apiGroups: [""]
//!   resources: ["secrets"]
//!   verbs: ["get", "list", "watch"]
//! ```
//!
//! granted through a namespaced `Role`/`RoleBinding` in `ferriscd-system` (or a `ClusterRole`
//! that is *bound* namespaced — a `ClusterRole` alone grants nothing). Never a cluster-wide
//! `Secret` read: `T13.1`'s cluster registry will read its own
//! `ferriscd.io/secret-type=cluster` `Secret`s from the same namespace under the same rule.

use std::collections::BTreeMap;
use std::fmt;

use ferriscd_crd::CONTROL_PLANE_NAMESPACE;
use ferriscd_engine::manifest::redact_repo_url;
use ferriscd_engine::repo::RepoCredentials;
use futures::future::BoxFuture;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use kube::ResourceExt as _;
use kube::api::{Api, ListParams};

use crate::reconcile::ReconcileError;

/// Label key that opts a `Secret` in as a FerrisCD credential.
pub const SECRET_TYPE_LABEL: &str = "ferriscd.io/secret-type";

/// Label value selecting Git repository credentials.
pub const SECRET_TYPE_REPOSITORY: &str = "repository";

/// Secret data key holding the repository URL, or the prefix every match must start with.
pub const KEY_URL: &str = "url";

/// Secret data key holding an HTTPS basic-auth user name.
pub const KEY_USERNAME: &str = "username";

/// Secret data key holding an HTTPS basic-auth password (or a bearer token when `username` is
/// absent).
pub const KEY_PASSWORD: &str = "password";

/// Secret data key holding an HTTPS bearer / personal access token.
pub const KEY_TOKEN: &str = "token";

/// Secret data key holding an unencrypted SSH private key.
///
/// Passphrase-protected keys are not supported (the engine spawns `ssh` non-interactively), so a
/// passphrase cannot be supplied and is not read.
pub const KEY_SSH_PRIVATE_KEY: &str = "sshPrivateKey";

/// Secret data key holding the `known_hosts` entry of the SSH host.
///
/// Optional, but strict host key verification is the default: without it the clone fails
/// terminally with `RepoError::HostKeyVerificationFailed` unless the operator explicitly allowed
/// missing host keys (a test/dev-only switch). The `Secret` cannot weaken that policy.
pub const KEY_KNOWN_HOSTS: &str = "knownHosts";

/// `https` scheme name.
const SCHEME_HTTPS: &str = "https";

/// `http` scheme name.
///
/// Recognized only so the error can explain *why* a plaintext template is refused.
const SCHEME_HTTP: &str = "http";

/// `ssh` scheme name.
const SCHEME_SSH: &str = "ssh";

/// Problems with a repository credential `Secret`.
///
/// Every variant is **terminal**: no reconcile can repair a mislabeled or ambiguous `Secret`, and
/// picking a credential the operator did not mean is exactly the confused-deputy failure this
/// module exists to prevent. No variant carries a secret value.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// One `Secret`'s contents cannot be turned into credentials.
    #[error(
        "repository credential Secret {secret} in namespace {namespace:?} cannot be used: \
         {reason}"
    )]
    Malformed {
        /// Name of the offending `Secret`.
        secret: String,
        /// Namespace it was read from (the control-plane namespace).
        namespace: String,
        /// Actionable, secret-free description of what is wrong.
        reason: String,
    },

    /// Two `Secret`s claim the same repository URL.
    #[error(
        "two repository credential Secrets in namespace {namespace:?} declare the same repository \
         url {url}: {secrets}. Keep exactly one of them, or narrow one of them to a more specific \
         prefix (the longest matching prefix wins)"
    )]
    DuplicateUrl {
        /// Namespace both `Secret`s live in.
        namespace: String,
        /// The shared, redacted URL.
        url: String,
        /// The colliding `Secret` names.
        secrets: String,
    },
}

impl CredentialError {
    /// Whether the error can never be fixed by retrying.
    ///
    /// Always `true`: these are configuration errors in a `Secret` the controller does not write.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        true
    }
}

/// Reads the credentials one repository URL is cloned with.
///
/// The seam exists so the sync pipeline never talks to the API server directly: production wires
/// [`SecretCredentialStore`], hermetic tests wire a map, and a pipeline with no source at all
/// clones anonymously (the pre-`T12.4` behaviour, still correct for public repositories).
pub trait CredentialSource: Send + Sync + 'static {
    /// Returns the credentials to use for `repo_url`.
    ///
    /// `Ok(RepoCredentials::Anonymous)` — never an error — when no `Secret` matches.
    ///
    /// # Errors
    ///
    /// [`CredentialError`] (terminal) for an unusable `Secret`, and any API failure of the
    /// (namespaced) read itself.
    fn credentials_for<'a>(
        &'a self,
        repo_url: &'a str,
    ) -> BoxFuture<'a, Result<RepoCredentials, ReconcileError>>;
}

/// One credential template: a normalized repository URL prefix plus the credentials it supplies.
///
/// Built by [`Self::from_secret`]; [`Match`]-ing is pure, so the whole matching contract is
/// testable without a cluster.
#[derive(Clone)]
pub struct CredentialTemplate {
    /// `<namespace>/<name>` of the `Secret` this template came from (diagnostics only).
    secret: String,
    /// Control-plane namespace the `Secret` lives in.
    namespace: String,
    /// Normalized repository URL prefix (see [`normalize_repo_url`]).
    url_prefix: String,
    /// The credentials handed to the Git client. Redacted in every `Debug`/`Display`.
    credentials: RepoCredentials,
}

impl CredentialTemplate {
    /// Parses `secret` into a template.
    ///
    /// Returns `Ok(None)` — *ignored*, not an error — when the `Secret` does not carry
    /// `ferriscd.io/secret-type: repository`: the label is the opt-in, so a `Secret` that merely
    /// exists in the namespace is never used as a credential (and a mislabeled one cannot be
    /// matched by accident).
    ///
    /// # Errors
    ///
    /// [`CredentialError::Malformed`] for a labeled `Secret` whose `url` or credential keys are
    /// missing, ambiguous, or inconsistent with the `url` scheme. The message names the `Secret`,
    /// the namespace, and the keys involved — never a value.
    pub fn from_secret(secret: &Secret) -> Result<Option<Self>, CredentialError> {
        if !is_repository_secret(secret) {
            return Ok(None);
        }
        let name = secret.name_any();
        let namespace = secret.namespace().unwrap_or_default();
        let ctx = SecretContext {
            secret: &name,
            namespace: &namespace,
        };

        let data = decode_data(secret, &ctx)?;
        let raw_url = value(&data, KEY_URL)
            .ok_or_else(|| ctx.malformed(format!("the {KEY_URL:?} key is missing or empty")))?;
        if embeds_userinfo(raw_url) {
            return Err(ctx.malformed(format!(
                "the {KEY_URL:?} key embeds credentials; move them into the {KEY_USERNAME:?}/\
                 {KEY_PASSWORD:?}/{KEY_TOKEN:?} keys so the URL can be logged safely"
            )));
        }
        let url_prefix = normalize_repo_url(raw_url).ok_or_else(|| {
            ctx.malformed(format!(
                "the {KEY_URL:?} key is not a usable repository URL (whitespace, control \
                 characters, and empty values are rejected)"
            ))
        })?;
        let scheme = scheme_of(&url_prefix).ok_or_else(|| {
            ctx.malformed(format!(
                "the {KEY_URL:?} key must be an absolute URL with a scheme, e.g. \
                 https://git.example.com or ssh://git.example.com"
            ))
        })?;

        let ssh_key = value(&data, KEY_SSH_PRIVATE_KEY);
        let username = value(&data, KEY_USERNAME);
        let password = value(&data, KEY_PASSWORD);
        let token = value(&data, KEY_TOKEN);
        let known_hosts = value(&data, KEY_KNOWN_HOSTS);

        let credentials = match scheme {
            SCHEME_SSH => {
                if username.is_some() || password.is_some() || token.is_some() {
                    return Err(ctx.malformed(format!(
                        "the {KEY_URL:?} key is an ssh:// repository but the Secret also carries \
                         {KEY_USERNAME:?}/{KEY_PASSWORD:?}/{KEY_TOKEN:?}; an SSH repository is \
                         authenticated by {KEY_SSH_PRIVATE_KEY:?} only"
                    )));
                }
                let private_key_pem = ssh_key.ok_or_else(|| {
                    ctx.malformed(format!(
                        "the {KEY_URL:?} key is an ssh:// repository, so the {KEY_SSH_PRIVATE_KEY:?} \
                         key is required"
                    ))
                })?;
                RepoCredentials::SshKey {
                    private_key_pem: private_key_pem.to_owned(),
                    // Passphrase-protected keys cannot be used: `ssh` runs non-interactively.
                    passphrase: None,
                    known_hosts: known_hosts.map(ToOwned::to_owned),
                }
            }
            SCHEME_HTTPS => {
                if ssh_key.is_some() {
                    return Err(ctx.malformed(format!(
                        "the {KEY_URL:?} key is an {scheme}:// repository but the Secret carries \
                         {KEY_SSH_PRIVATE_KEY:?}; an HTTPS repository is authenticated by \
                         {KEY_USERNAME:?}/{KEY_PASSWORD:?}/{KEY_TOKEN:?} only"
                    )));
                }
                if known_hosts.is_some() {
                    return Err(ctx.malformed(format!(
                        "{KEY_KNOWN_HOSTS:?} only applies to ssh:// repositories"
                    )));
                }
                http_credentials(&ctx, &data, username, password, token)?
            }
            // A plaintext template is refused rather than accepted-and-unusable: FerrisCD's Git
            // layer never clones `http://` (the URL policy rejects it and the transport refuses to
            // send credentials in clear text), so a `Secret` that asks for it is an operator
            // mistake — and one that should never be able to leak a token even by accident.
            SCHEME_HTTP => {
                return Err(ctx.malformed(format!(
                    "the {KEY_URL:?} key uses plaintext {SCHEME_HTTP}://, which FerrisCD never uses \
                     for repository credentials (the credential would travel in the clear): use \
                     {SCHEME_HTTPS}:// or {SCHEME_SSH}://"
                )));
            }
            other => {
                return Err(ctx.malformed(format!(
                    "the {KEY_URL:?} key scheme {other:?} is not supported: only {SCHEME_HTTPS}:// \
                     and {SCHEME_SSH}:// repositories can carry credentials"
                )));
            }
        };

        Ok(Some(Self {
            secret: format!("{namespace}/{name}"),
            namespace,
            url_prefix,
            credentials,
        }))
    }

    /// `<namespace>/<name>` of the `Secret` this template came from.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Control-plane namespace the `Secret` lives in.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The normalized URL prefix this template matches.
    ///
    /// Already userinfo-free by construction; format it through [`redact_repo_url`] when it goes
    /// into a log line or a status message anyway (defense in depth).
    #[must_use]
    pub fn url_prefix(&self) -> &str {
        &self.url_prefix
    }

    /// The credentials this template supplies.
    ///
    /// Never log this directly: [`RepoCredentials`]' own `Debug`/`Display` redact the values, but
    /// callers should prefer [`RepoCredentials::to_string`](ToString::to_string), which reports
    /// only the credential kind.
    #[must_use]
    pub fn credentials(&self) -> &RepoCredentials {
        &self.credentials
    }

    /// Whether this template matches `normalized_url` (already passed through
    /// [`normalize_repo_url`]; [`match_credentials`] is the entry point that does both).
    ///
    /// An exact match always counts; a prefix only counts on a path-segment boundary, so
    /// `https://git.example.com/org` never matches `https://git.example.com/organization/repo`
    /// or `https://git.example.com.evil/repo`.
    #[must_use]
    pub fn matches(&self, normalized_url: &str) -> bool {
        if normalized_url == self.url_prefix {
            return true;
        }
        match normalized_url.strip_prefix(&self.url_prefix) {
            // `https://git.example.com` + `/org/repo`
            Some(rest) => rest.starts_with('/'),
            None => false,
        }
    }
}

impl fmt::Debug for CredentialTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialTemplate")
            .field("secret", &self.secret)
            .field("url_prefix", &redact_repo_url(&self.url_prefix))
            // `RepoCredentials`' `Debug` prints `[REDACTED]` for every secret field.
            .field("credentials", &self.credentials)
            .finish()
    }
}

impl fmt::Display for CredentialTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}) <- {}",
            redact_repo_url(&self.url_prefix),
            self.credentials,
            self.secret
        )
    }
}

/// Builds the template set from the `Secret`s a namespaced list returned.
///
/// Unlabeled `Secret`s are skipped ([`CredentialTemplate::from_secret`]), and two `Secret`s that
/// claim the same repository URL are a terminal [`CredentialError::DuplicateUrl`] instead of a
/// silently chosen winner — an ambiguous credential makes "which token was used?" unanswerable.
///
/// # Errors
///
/// [`CredentialError`] for the first unusable or duplicated `Secret`.
pub fn templates_from_secrets(
    secrets: &[Secret],
) -> Result<Vec<CredentialTemplate>, CredentialError> {
    let mut templates = Vec::with_capacity(secrets.len());
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for secret in secrets {
        let Some(template) = CredentialTemplate::from_secret(secret)? else {
            continue;
        };
        if let Some(existing) = seen.get(template.url_prefix()) {
            return Err(CredentialError::DuplicateUrl {
                namespace: template.namespace().to_owned(),
                url: redact_repo_url(template.url_prefix()),
                secrets: format!("{existing}, {}", template.secret()),
            });
        }
        seen.insert(
            template.url_prefix().to_owned(),
            template.secret().to_owned(),
        );
        templates.push(template);
    }
    Ok(templates)
}

/// Selects the template that supplies `repo_url`'s credentials.
///
/// The longest matching prefix wins (an exact match is just the longest possible prefix), so a
/// host-wide template and a repository-specific one can coexist and the specific one always
/// applies. A URL that normalizes to nothing (whitespace, control characters) matches nothing.
#[must_use]
pub fn match_credentials<'a>(
    templates: &'a [CredentialTemplate],
    repo_url: &str,
) -> Option<&'a CredentialTemplate> {
    let normalized = normalize_repo_url(repo_url)?;
    templates
        .iter()
        .filter(|template| template.matches(&normalized))
        .max_by_key(|template| template.url_prefix().len())
}

/// Normalizes a repository URL for credential matching.
///
/// The exact rules are documented on the [module](self); the important properties are that the
/// function is **pure**, that it never fails for an unusable URL (it returns `None`), and that a
/// normalized URL never contains userinfo — so it is always safe to log.
///
/// The result is **lowercased as a whole, path included** (see the module docs for why): two URLs
/// that differ only in path case normalize to the same string.
///
/// Returns `None` for a blank URL and for one containing whitespace or control characters (an
/// HTTP header / Git argument cannot carry those anyway).
#[must_use]
pub fn normalize_repo_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }

    let normalized = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            let scheme = scheme.to_ascii_lowercase();
            let authority_and_path = strip_default_port(&strip_userinfo(rest), &scheme);
            format!("{scheme}://{}", trim_repository_suffix(&authority_and_path))
        }
        // `git@github.com:org/repo.git` is an SCP-style remote: the same repository as
        // `ssh://github.com/org/repo`, so it normalizes to that form.
        None => match split_scp_style(trimmed) {
            Some((host, path)) => format!(
                "{SCHEME_SSH}://{}",
                trim_repository_suffix(&format!("{host}/{path}"))
            ),
            // A bare local path (`/tmp/repo`) or anything else: kept as-is. No credential
            // template can match it, because a template must carry a supported scheme.
            None => trim_repository_suffix(trimmed).to_owned(),
        },
    };

    Some(normalized.to_ascii_lowercase())
}

/// Splits an SCP-style SSH remote (`[user@]host:path`) into `(host, path)`.
fn split_scp_style(raw: &str) -> Option<(&str, &str)> {
    let (authority, path) = raw.split_once(':')?;
    if path.is_empty() {
        return None;
    }
    // `https://…` is handled before this function is called; a `rest:port`-only shape is not a
    // remote, and neither is a path with a slash before the colon.
    let host = match authority.rsplit_once('@') {
        Some((_user, host)) => host,
        None => authority,
    };
    if host.is_empty() || host.contains('/') || host.contains(['@', '\\', '[', ']']) {
        return None;
    }
    Some((host, path))
}

/// Drops the userinfo of an authority (`user:token@host` → `host`), leaving the path untouched.
fn strip_userinfo(rest: &str) -> String {
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (rest, None),
    };
    match (strip_authority_userinfo(authority), path) {
        (Some(host), Some(path)) => format!("{host}/{path}"),
        (Some(host), None) => host.to_owned(),
        (None, _) => rest.to_owned(),
    }
}

/// Returns `authority` without its userinfo, or `None` when it has none.
fn strip_authority_userinfo(authority: &str) -> Option<&str> {
    authority
        .rsplit_once('@')
        .map(|(_userinfo, host)| host)
        .filter(|host| !host.is_empty())
}

/// Removes the scheme's default port (`:443`, `:80`, `:22`) from an authority.
///
/// `https://git.example.com:443/org` and `https://git.example.com/org` are the same endpoint, so a
/// `Secret` written either way must match either spelling. A non-default port stays part of the
/// key: `ssh://git.example.com:2222/org` is a different server.
fn strip_default_port(value: &str, scheme: &str) -> String {
    let default_port = match scheme {
        SCHEME_HTTPS => ":443",
        SCHEME_HTTP => ":80",
        SCHEME_SSH => ":22",
        _ => return value.to_owned(),
    };
    let (authority, path) = match value.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (value, None),
    };
    let Some(host) = authority.strip_suffix(default_port) else {
        return value.to_owned();
    };
    if host.is_empty() {
        return value.to_owned();
    }
    match path {
        Some(path) => format!("{host}/{path}"),
        None => host.to_owned(),
    }
}

/// Removes trailing slashes and one trailing `.git` from a repository path.
fn trim_repository_suffix(value: &str) -> &str {
    let trimmed = value.trim_end_matches('/');
    match trimmed.strip_suffix(".git") {
        Some(stripped) => stripped.trim_end_matches('/'),
        None => trimmed,
    }
}

/// Returns the lowercased scheme of a normalized URL.
fn scheme_of(normalized: &str) -> Option<&str> {
    normalized.split_once("://").map(|(scheme, _rest)| scheme)
}

/// Whether `raw` carries `user:password@` (or `token@`) userinfo in an `https`/`http` URL.
///
/// Only HTTP(S) URLs are checked: an `ssh://` URL legitimately carries the SSH user
/// (`ssh://git@github.com/…`), which is not a secret and is dropped by normalization.
fn embeds_userinfo(raw: &str) -> bool {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case(SCHEME_HTTPS) && !scheme.eq_ignore_ascii_case(SCHEME_HTTP) {
        return false;
    }
    let authority = rest
        .split_once('/')
        .map_or(rest, |(authority, _)| authority);
    authority.contains('@')
}

/// Whether `secret` carries the `ferriscd.io/secret-type: repository` label.
fn is_repository_secret(secret: &Secret) -> bool {
    secret
        .labels()
        .get(SECRET_TYPE_LABEL)
        .is_some_and(|value| value.trim() == SECRET_TYPE_REPOSITORY)
}

/// The `Secret` a parse error belongs to, so messages can name it without repeating the plumbing.
struct SecretContext<'a> {
    secret: &'a str,
    namespace: &'a str,
}

impl SecretContext<'_> {
    /// Builds a terminal [`CredentialError::Malformed`] for this `Secret`.
    fn malformed(&self, reason: impl Into<String>) -> CredentialError {
        CredentialError::Malformed {
            secret: self.secret.to_owned(),
            namespace: self.namespace.to_owned(),
            reason: reason.into(),
        }
    }
}

/// Decodes a `Secret`'s `data` (and `stringData`) into plain-text values.
///
/// `data` wins over `stringData` per key. A non-UTF-8 value is reported by **key name** only: the
/// value may be a private key, and the error ends up in `Application.status`.
fn decode_data(
    secret: &Secret,
    ctx: &SecretContext<'_>,
) -> Result<BTreeMap<String, String>, CredentialError> {
    let mut decoded = BTreeMap::new();
    for (key, value) in secret.string_data.as_ref().into_iter().flatten() {
        decoded.insert(key.clone(), value.clone());
    }
    for (key, ByteString(bytes)) in secret.data.as_ref().into_iter().flatten() {
        let value = String::from_utf8(bytes.clone()).map_err(|_| {
            ctx.malformed(format!(
                "the {key:?} key is not valid UTF-8, so it cannot be used as credential material"
            ))
        })?;
        decoded.insert(key.clone(), value);
    }
    Ok(decoded)
}

/// Returns `data[key]` trimmed, treating a blank value as absent.
fn value<'a>(data: &'a BTreeMap<String, String>, key: &str) -> Option<&'a str> {
    data.get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

/// Builds the HTTPS credential from the `username`/`password`/`token` keys.
///
/// The mapping is exactly the one `gix`'s HTTP transport can express (HTTP Basic):
///
/// * `username` + `password` → [`RepoCredentials::HttpBasic`];
/// * `username` + `token` → [`RepoCredentials::HttpBasic`] with the token as the password (the
///   GitHub/GitLab "user + personal access token" form);
/// * `token` alone → [`RepoCredentials::HttpToken`] (mapped to `username = token` by the engine);
/// * `password` alone → [`RepoCredentials::HttpToken`] with the password as the token.
fn http_credentials(
    ctx: &SecretContext<'_>,
    data: &BTreeMap<String, String>,
    username: Option<&str>,
    password: Option<&str>,
    token: Option<&str>,
) -> Result<RepoCredentials, CredentialError> {
    // Re-read the raw keys so a *blank* value is reported rather than silently treated as absent.
    let blank = |key: &str| data.get(key).is_some_and(|value| value.trim().is_empty());
    for key in [KEY_USERNAME, KEY_PASSWORD, KEY_TOKEN] {
        if blank(key) {
            return Err(ctx.malformed(format!(
                "the {key:?} key is present but empty; remove it or give it a value"
            )));
        }
    }

    match (username, password, token) {
        (Some(username), Some(password), None) => Ok(RepoCredentials::HttpBasic {
            username: username.to_owned(),
            password: password.to_owned(),
        }),
        (Some(username), None, Some(token)) => Ok(RepoCredentials::HttpBasic {
            username: username.to_owned(),
            password: token.to_owned(),
        }),
        (None, None, Some(token)) => Ok(RepoCredentials::HttpToken {
            token: token.to_owned(),
        }),
        (None, Some(password), None) => Ok(RepoCredentials::HttpToken {
            token: password.to_owned(),
        }),
        (Some(_), Some(_), Some(_)) => Err(ctx.malformed(format!(
            "both {KEY_PASSWORD:?} and {KEY_TOKEN:?} are set next to {KEY_USERNAME:?}; keep one of \
             them so the request cannot present two credentials"
        ))),
        (None, Some(_), Some(_)) => Err(ctx.malformed(format!(
            "both {KEY_PASSWORD:?} and {KEY_TOKEN:?} are set without {KEY_USERNAME:?}; keep one of \
             them so the request cannot present two credentials"
        ))),
        (Some(_), None, None) => Err(ctx.malformed(format!(
            "{KEY_USERNAME:?} is set without {KEY_PASSWORD:?} or {KEY_TOKEN:?}"
        ))),
        (None, None, None) => Err(ctx.malformed(format!(
            "no credential keys are set: provide {KEY_USERNAME:?} + {KEY_PASSWORD:?}, \
             {KEY_TOKEN:?}, or {KEY_SSH_PRIVATE_KEY:?}"
        ))),
    }
}

/// [`CredentialSource`] backed by labeled `Secret`s in the control-plane namespace.
///
/// The `Api<Secret>` is built with [`Api::namespaced`], so no code path in this type can request a
/// cluster-wide `Secret` list. One read happens per [`CredentialSource::credentials_for`] call: a
/// scoped, label-filtered list (never a background informer), which keeps the controller's RBAC
/// requirement to `get`/`list`/`watch` Secrets in one namespace.
#[derive(Clone)]
pub struct SecretCredentialStore {
    api: Api<Secret>,
    namespace: String,
}

impl SecretCredentialStore {
    /// Builds a store reading from `namespace` (the control-plane namespace).
    #[must_use]
    pub fn new(client: kube::Client, namespace: &str) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            namespace: namespace.to_owned(),
        }
    }

    /// Builds a store reading from [`CONTROL_PLANE_NAMESPACE`] (`ferriscd-system`).
    #[must_use]
    pub fn in_control_plane(client: kube::Client) -> Self {
        Self::new(client, CONTROL_PLANE_NAMESPACE)
    }

    /// The namespace credentials are read from.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The label selector every list uses (`ferriscd.io/secret-type=repository`).
    #[must_use]
    pub fn label_selector() -> String {
        format!("{SECRET_TYPE_LABEL}={SECRET_TYPE_REPOSITORY}")
    }

    /// Lists and parses the credential `Secret`s of the control-plane namespace.
    ///
    /// # Errors
    ///
    /// [`ReconcileError::Credentials`] for an unusable `Secret`, and
    /// [`ReconcileError::Api`] when the (namespaced, label-filtered) list itself fails — the
    /// latter retries, the former does not.
    pub async fn templates(&self) -> Result<Vec<CredentialTemplate>, ReconcileError> {
        let params = ListParams::default().labels(&Self::label_selector());
        let secrets = self
            .api
            .list(&params)
            .await
            .map_err(ReconcileError::Api)?
            .items;
        templates_from_secrets(&secrets).map_err(ReconcileError::Credentials)
    }
}

impl fmt::Debug for SecretCredentialStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No `Api` internals (a client), and nothing derived from a `Secret` payload.
        f.debug_struct("SecretCredentialStore")
            .field("namespace", &self.namespace)
            .field("label_selector", &Self::label_selector())
            .finish_non_exhaustive()
    }
}

impl CredentialSource for SecretCredentialStore {
    fn credentials_for<'a>(
        &'a self,
        repo_url: &'a str,
    ) -> BoxFuture<'a, Result<RepoCredentials, ReconcileError>> {
        Box::pin(async move {
            let templates = self.templates().await?;
            match match_credentials(&templates, repo_url) {
                Some(template) => {
                    tracing::debug!(
                        repo = %redact_repo_url(repo_url),
                        secret = %template.secret(),
                        credentials = %template.credentials(),
                        "matched repository credential Secret"
                    );
                    Ok(template.credentials().clone())
                }
                None => {
                    tracing::debug!(
                        repo = %redact_repo_url(repo_url),
                        namespace = %self.namespace,
                        "no repository credential Secret matched; cloning anonymously"
                    );
                    Ok(RepoCredentials::Anonymous)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    const TOKEN: &str = "ghp_super_secret_token_987654";
    const PASSWORD: &str = "super-secret-password-xyz";
    const KEY_BODY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_KEY_BODY\n-----END OPENSSH PRIVATE KEY-----";
    const KNOWN_HOSTS: &str = "git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKNOWNHOST";

    /// Builds a labeled repository `Secret` in the control-plane namespace.
    fn secret(name: &str, data: &[(&str, &str)]) -> Secret {
        secret_in(CONTROL_PLANE_NAMESPACE, name, data)
    }

    /// Builds a labeled repository `Secret` in `namespace`.
    fn secret_in(namespace: &str, name: &str, data: &[(&str, &str)]) -> Secret {
        let mut secret = Secret {
            data: Some(
                data.iter()
                    .map(|(key, value)| ((*key).to_owned(), ByteString(value.as_bytes().to_vec())))
                    .collect::<BTreeMap<_, _>>(),
            ),
            ..Secret::default()
        };
        secret.metadata.name = Some(name.to_owned());
        secret.metadata.namespace = Some(namespace.to_owned());
        secret.metadata.labels = Some(BTreeMap::from([(
            SECRET_TYPE_LABEL.to_owned(),
            SECRET_TYPE_REPOSITORY.to_owned(),
        )]));
        secret
    }

    /// Parses one `Secret` into a template, panicking when it is not a usable credential.
    fn template(name: &str, data: &[(&str, &str)]) -> CredentialTemplate {
        CredentialTemplate::from_secret(&secret(name, data))
            .expect("the fixture Secret must parse")
            .expect("the fixture Secret must be labeled as a repository credential")
    }

    // ---------------------------------------------------------------------
    // Matching
    // ---------------------------------------------------------------------

    #[test]
    fn an_exact_url_wins_over_every_prefix() {
        let templates = vec![
            CredentialTemplate::from_secret(&secret(
                "host",
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_TOKEN, "host-token"),
                ],
            ))
            .expect("parse")
            .expect("labeled"),
            CredentialTemplate::from_secret(&secret(
                "repo",
                &[
                    (KEY_URL, "https://git.example.com/org/repo"),
                    (KEY_TOKEN, "repo-token"),
                ],
            ))
            .expect("parse")
            .expect("labeled"),
        ];

        let exact =
            match_credentials(&templates, "https://git.example.com/org/repo").expect("match");
        assert_eq!(exact.secret(), "ferriscd-system/repo");
        // `.git` and a trailing slash are the same repository.
        let with_git =
            match_credentials(&templates, "https://git.example.com/org/repo.git/").expect("match");
        assert_eq!(with_git.secret(), "ferriscd-system/repo");
        // Anything else on the host still matches the host-wide template.
        let other =
            match_credentials(&templates, "https://git.example.com/org/other").expect("match");
        assert_eq!(other.secret(), "ferriscd-system/host");
    }

    #[test]
    fn the_longest_prefix_wins_and_prefixes_never_match_across_a_segment_boundary() {
        let templates = vec![
            CredentialTemplate::from_secret(&secret(
                "host",
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_TOKEN, "host-token"),
                ],
            ))
            .expect("parse")
            .expect("labeled"),
            CredentialTemplate::from_secret(&secret(
                "org",
                &[
                    (KEY_URL, "https://git.example.com/org"),
                    (KEY_TOKEN, "org-token"),
                ],
            ))
            .expect("parse")
            .expect("labeled"),
        ];

        let deep =
            match_credentials(&templates, "https://git.example.com/org/team/repo").expect("match");
        assert_eq!(deep.secret(), "ferriscd-system/org");

        // A prefix is a path prefix, not a string prefix: `organization` is not `org`.
        let lookalike = match_credentials(&templates, "https://git.example.com/organization/repo")
            .expect("the host template still matches");
        assert_eq!(lookalike.secret(), "ferriscd-system/host");

        // ...and a lookalike *host* never matches, despite the shared prefix.
        assert!(
            match_credentials(&templates, "https://git.example.com.evil/org/repo").is_none(),
            "a host suffix must never satisfy a prefix template"
        );
        assert!(
            match_credentials(&templates, "https://notgit.example.com/org/repo").is_none(),
            "a host prefix must not match a longer host"
        );
    }

    #[test]
    fn a_bare_host_prefix_matches_every_repository_on_that_host() {
        let template = template(
            "host",
            &[(KEY_URL, "https://git.example.com/"), (KEY_TOKEN, TOKEN)],
        );
        assert_eq!(template.url_prefix(), "https://git.example.com");
        for url in [
            "https://git.example.com/org/repo.git",
            "https://git.example.com/repo",
            "HTTPS://GIT.EXAMPLE.COM/org/repo",
            "https://git.example.com:443/org/repo",
        ] {
            assert!(
                match_credentials(std::slice::from_ref(&template), url).is_some(),
                "the host template must match {url}"
            );
        }
        assert!(
            match_credentials(&[template], "https://git.example.com.evil/repo").is_none(),
            "a host template must not match a different host"
        );
    }

    #[test]
    fn dot_git_slashes_and_case_are_normalized_on_both_sides() {
        // The Secret spells it one way, the Application the other.
        for (secret_url, repo_url) in [
            (
                "https://git.example.com/org/repo.git",
                "https://git.example.com/org/repo",
            ),
            (
                "https://git.example.com/org/repo",
                "https://git.example.com/org/repo.git/",
            ),
            (
                "HTTPS://Git.Example.COM/Org/Repo",
                "https://git.example.com/org/repo",
            ),
            (
                "https://git.example.com/org/repo///",
                "https://git.example.com/org/repo",
            ),
        ] {
            let template = template("creds", &[(KEY_URL, secret_url), (KEY_TOKEN, TOKEN)]);
            assert_eq!(
                template.url_prefix(),
                "https://git.example.com/org/repo",
                "the template must normalize {secret_url}"
            );
            assert!(
                match_credentials(std::slice::from_ref(&template), repo_url).is_some(),
                "{secret_url} must match {repo_url}"
            );
        }

        // The scheme is *not* normalized away: https and ssh are different transports with
        // different credentials.
        let https = template(
            "https",
            &[
                (KEY_URL, "https://git.example.com/org/repo"),
                (KEY_TOKEN, TOKEN),
            ],
        );
        assert!(
            match_credentials(&[https], "ssh://git.example.com/org/repo").is_none(),
            "an https credential must never leak into an ssh clone"
        );
    }

    #[test]
    fn scp_style_and_ssh_urls_normalize_to_the_same_repository() {
        let scp = template(
            "scp",
            &[
                (KEY_URL, "git@git.example.com:org/repo.git"),
                (KEY_SSH_PRIVATE_KEY, KEY_BODY),
                (KEY_KNOWN_HOSTS, KNOWN_HOSTS),
            ],
        );
        assert_eq!(scp.url_prefix(), "ssh://git.example.com/org/repo");
        assert!(
            match_credentials(
                std::slice::from_ref(&scp),
                "ssh://git@git.example.com/org/repo"
            )
            .is_some(),
            "the ssh user is not part of the repository identity"
        );
        assert!(
            match_credentials(&[scp], "git@git.example.com:org/repo").is_some(),
            "the SCP-style form of the Application URL must match too"
        );

        let ssh = template(
            "ssh",
            &[
                (KEY_URL, "ssh://git@git.example.com:2222/org/repo"),
                (KEY_SSH_PRIVATE_KEY, KEY_BODY),
            ],
        );
        assert_eq!(ssh.url_prefix(), "ssh://git.example.com:2222/org/repo");
        assert!(
            match_credentials(
                std::slice::from_ref(&ssh),
                "ssh://deploy@git.example.com:2222/org/repo"
            )
            .is_some(),
            "the ssh user is dropped from both sides"
        );
        assert!(
            match_credentials(&[ssh], "ssh://git@git.example.com/org/repo").is_none(),
            "a non-default port is part of the endpoint"
        );
    }

    #[test]
    fn no_match_is_anonymous_not_an_error() {
        let templates = vec![template(
            "host",
            &[(KEY_URL, "https://git.example.com"), (KEY_TOKEN, TOKEN)],
        )];
        for url in [
            "https://other.example.com/org/repo",
            "/tmp/local-repo",
            "file:///tmp/local-repo",
            "not a url at all",
            "",
        ] {
            assert!(
                match_credentials(&templates, url).is_none(),
                "{url:?} must not match any template"
            );
        }
    }

    // ---------------------------------------------------------------------
    // Credential mapping
    // ---------------------------------------------------------------------

    #[test]
    fn https_secrets_map_to_basic_and_token_credentials() {
        let cases: &[(&[(&str, &str)], RepoCredentials)] = &[
            (
                &[(KEY_URL, "https://git.example.com"), (KEY_TOKEN, TOKEN)],
                RepoCredentials::HttpToken {
                    token: TOKEN.to_owned(),
                },
            ),
            (
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_PASSWORD, PASSWORD),
                ],
                RepoCredentials::HttpToken {
                    token: PASSWORD.to_owned(),
                },
            ),
            (
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_USERNAME, "ci-bot"),
                    (KEY_PASSWORD, PASSWORD),
                ],
                RepoCredentials::HttpBasic {
                    username: "ci-bot".to_owned(),
                    password: PASSWORD.to_owned(),
                },
            ),
            (
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_USERNAME, "ci-bot"),
                    (KEY_TOKEN, TOKEN),
                ],
                RepoCredentials::HttpBasic {
                    username: "ci-bot".to_owned(),
                    password: TOKEN.to_owned(),
                },
            ),
        ];

        for (data, expected) in cases {
            let parsed = template("creds", data);
            assert_eq!(
                parsed.credentials(),
                expected,
                "unexpected mapping for {data:?}"
            );
            assert_eq!(parsed.url_prefix(), "https://git.example.com");
        }
    }

    #[test]
    fn ssh_secrets_map_to_key_credentials_with_host_key_pinning() {
        let with_hosts = template(
            "ssh",
            &[
                (KEY_URL, "ssh://git.example.com/org/repo"),
                (KEY_SSH_PRIVATE_KEY, KEY_BODY),
                (KEY_KNOWN_HOSTS, KNOWN_HOSTS),
            ],
        );
        assert_eq!(
            with_hosts.credentials(),
            &RepoCredentials::SshKey {
                private_key_pem: KEY_BODY.to_owned(),
                passphrase: None,
                known_hosts: Some(KNOWN_HOSTS.to_owned()),
            }
        );

        // A missing `knownHosts` is not silently tolerated here: the engine's strict host key
        // policy refuses the clone, which is where the operator-visible error belongs.
        let without_hosts = template(
            "ssh",
            &[
                (KEY_URL, "ssh://git.example.com"),
                (KEY_SSH_PRIVATE_KEY, KEY_BODY),
            ],
        );
        assert_eq!(
            without_hosts.credentials(),
            &RepoCredentials::SshKey {
                private_key_pem: KEY_BODY.to_owned(),
                passphrase: None,
                known_hosts: None,
            }
        );
    }

    #[test]
    fn string_data_is_accepted_so_a_hand_written_fixture_stays_readable() {
        let mut secret = Secret {
            string_data: Some(BTreeMap::from([
                (KEY_URL.to_owned(), "https://git.example.com".to_owned()),
                (KEY_TOKEN.to_owned(), TOKEN.to_owned()),
            ])),
            ..Secret::default()
        };
        secret.metadata.name = Some("creds".to_owned());
        secret.metadata.namespace = Some(CONTROL_PLANE_NAMESPACE.to_owned());
        secret.metadata.labels = Some(BTreeMap::from([(
            SECRET_TYPE_LABEL.to_owned(),
            SECRET_TYPE_REPOSITORY.to_owned(),
        )]));

        let parsed = CredentialTemplate::from_secret(&secret)
            .expect("stringData must parse")
            .expect("labeled");
        assert_eq!(
            parsed.credentials(),
            &RepoCredentials::HttpToken {
                token: TOKEN.to_owned()
            }
        );
    }

    // ---------------------------------------------------------------------
    // Label filter & malformed secrets
    // ---------------------------------------------------------------------

    #[test]
    fn an_unlabeled_or_differently_labeled_secret_is_ignored() {
        for labels in [
            None,
            Some(BTreeMap::from([(
                SECRET_TYPE_LABEL.to_owned(),
                "cluster".to_owned(),
            )])),
            Some(BTreeMap::from([("other".to_owned(), "value".to_owned())])),
        ] {
            let mut secret = secret(
                "creds",
                &[(KEY_URL, "https://git.example.com"), (KEY_TOKEN, TOKEN)],
            );
            secret.metadata.labels = labels;
            assert!(
                CredentialTemplate::from_secret(&secret)
                    .expect("an ignored Secret is not an error")
                    .is_none(),
                "only ferriscd.io/secret-type=repository opts a Secret in"
            );
        }

        // The selector the store sends is the same label, so the API server filters it too.
        assert_eq!(
            SecretCredentialStore::label_selector(),
            "ferriscd.io/secret-type=repository"
        );
    }

    #[test]
    fn ambiguous_or_incomplete_secrets_are_terminal_errors_that_name_the_keys() {
        // `(data, expected fragment of the message)`
        let cases: &[(&[(&str, &str)], &str)] = &[
            (&[(KEY_TOKEN, TOKEN)], "the \"url\" key"),
            (
                &[(KEY_URL, "/tmp/repo"), (KEY_TOKEN, TOKEN)],
                "must be an absolute URL",
            ),
            (
                &[(KEY_URL, "file:///tmp/repo"), (KEY_TOKEN, TOKEN)],
                "scheme \"file\" is not supported",
            ),
            (
                &[
                    (KEY_URL, "http://127.0.0.1:8080/org/repo"),
                    (KEY_TOKEN, TOKEN),
                ],
                "uses plaintext http://",
            ),
            (
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_SSH_PRIVATE_KEY, KEY_BODY),
                ],
                "sshPrivateKey",
            ),
            (
                &[(KEY_URL, "ssh://git.example.com"), (KEY_TOKEN, TOKEN)],
                "authenticated by \"sshPrivateKey\" only",
            ),
            (
                &[(KEY_URL, "ssh://git.example.com")],
                "the \"sshPrivateKey\" key is required",
            ),
            (
                &[
                    (KEY_URL, "ssh://git.example.com"),
                    (KEY_SSH_PRIVATE_KEY, KEY_BODY),
                    (KEY_TOKEN, TOKEN),
                ],
                "authenticated by \"sshPrivateKey\" only",
            ),
            (
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_USERNAME, "u"),
                    (KEY_PASSWORD, PASSWORD),
                    (KEY_TOKEN, TOKEN),
                ],
                "both \"password\" and \"token\"",
            ),
            (
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_PASSWORD, PASSWORD),
                    (KEY_TOKEN, TOKEN),
                ],
                "without \"username\"",
            ),
            (
                &[(KEY_URL, "https://git.example.com"), (KEY_USERNAME, "u")],
                "without \"password\" or \"token\"",
            ),
            (
                &[(KEY_URL, "https://git.example.com"), (KEY_TOKEN, "   ")],
                "the \"token\" key is present but empty",
            ),
            (
                &[
                    (KEY_URL, "https://git.example.com"),
                    (KEY_KNOWN_HOSTS, KNOWN_HOSTS),
                    (KEY_TOKEN, TOKEN),
                ],
                "only applies to ssh://",
            ),
            (
                &[
                    (KEY_URL, "https://user:pass@git.example.com/org"),
                    (KEY_TOKEN, TOKEN),
                ],
                "embeds credentials",
            ),
        ];

        for (data, fragment) in cases {
            let fragment = *fragment;
            let err = CredentialTemplate::from_secret(&secret("repo-creds", data))
                .expect_err("the Secret must be refused");
            let terminal = err.is_terminal();
            let message = err.to_string();
            assert!(
                matches!(&err, CredentialError::Malformed { .. }),
                "{data:?} produced {err:?}"
            );
            assert!(
                message.contains(fragment),
                "{data:?}: expected {fragment:?} in {message}"
            );
            assert!(
                message.contains("ferriscd-system") && message.contains("repo-creds"),
                "the error must name the Secret and its namespace: {message}"
            );
            assert!(terminal);
        }
    }

    #[test]
    fn non_utf8_secret_data_is_refused_by_key_name_only() {
        let mut raw = secret("creds", &[(KEY_URL, "https://git.example.com")]);
        raw.data.as_mut().expect("data").insert(
            KEY_TOKEN.to_owned(),
            ByteString(vec![0xff, 0xfe, 0x00, 0x01]),
        );

        let err = CredentialTemplate::from_secret(&raw).expect_err("non-UTF-8 must be refused");
        let message = err.to_string();
        assert!(matches!(&err, CredentialError::Malformed { .. }), "{err:?}");
        assert!(message.contains("\"token\""), "{message}");
        assert!(message.contains("not valid UTF-8"), "{message}");
        assert!(
            !message.contains("\\u"),
            "the value must not be echoed: {message}"
        );
    }

    #[test]
    fn two_secrets_claiming_the_same_url_are_a_terminal_conflict() {
        let secrets = vec![
            secret(
                "first",
                &[
                    (KEY_URL, "https://git.example.com/org"),
                    (KEY_TOKEN, "first-token-value"),
                ],
            ),
            // The same URL spelled differently: normalization must collapse them.
            secret(
                "second",
                &[
                    (KEY_URL, "HTTPS://Git.Example.com/org/.git/"),
                    (KEY_TOKEN, "second-token-value"),
                ],
            ),
        ];

        let err = templates_from_secrets(&secrets).expect_err("a duplicate URL must be refused");
        let terminal = err.is_terminal();
        let message = err.to_string();
        assert!(
            matches!(&err, CredentialError::DuplicateUrl { .. }),
            "{err:?}"
        );
        assert!(
            message.contains("first") && message.contains("second"),
            "{message}"
        );
        assert!(message.contains("https://git.example.com/org"), "{message}");
        for token in ["first-token-value", "second-token-value"] {
            assert!(!message.contains(token), "{token} leaked into {message}");
        }
        assert!(terminal);
    }

    #[test]
    fn templates_skip_unlabeled_secrets_instead_of_failing_the_whole_list() {
        let mut unlabeled = secret(
            "unlabeled",
            &[(KEY_URL, "https://git.example.com"), (KEY_TOKEN, TOKEN)],
        );
        unlabeled.metadata.labels = None;
        let secrets = vec![
            unlabeled,
            secret(
                "labeled",
                &[(KEY_URL, "https://git.example.com"), (KEY_TOKEN, TOKEN)],
            ),
        ];

        let templates = templates_from_secrets(&secrets).expect("unlabeled Secrets are skipped");
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].secret(), "ferriscd-system/labeled");
    }

    // ---------------------------------------------------------------------
    // Secret hygiene
    // ---------------------------------------------------------------------

    #[test]
    fn no_debug_display_or_error_output_contains_secret_material() {
        let token_template = template(
            "token-creds",
            &[(KEY_URL, "https://git.example.com/org"), (KEY_TOKEN, TOKEN)],
        );
        let basic_template = template(
            "basic-creds",
            &[
                (KEY_URL, "https://git.example.com/org"),
                (KEY_USERNAME, "ci-user-secret"),
                (KEY_PASSWORD, PASSWORD),
            ],
        );
        let ssh_template = template(
            "ssh-creds",
            &[
                (KEY_URL, "ssh://git.example.com/org"),
                (KEY_SSH_PRIVATE_KEY, KEY_BODY),
                (KEY_KNOWN_HOSTS, KNOWN_HOSTS),
            ],
        );

        for (template, needles) in [
            (&token_template, &[TOKEN, "SECRET_KEY_BODY"][..]),
            (&basic_template, &["ci-user-secret", PASSWORD][..]),
            (&ssh_template, &["SECRET_KEY_BODY", KNOWN_HOSTS][..]),
        ] {
            let rendered = format!("{template:?} {template:#?} {template}");
            for needle in needles {
                assert!(
                    !rendered.contains(needle),
                    "{needle:?} leaked into {rendered}"
                );
            }
            assert!(rendered.contains("ferriscd-system/"), "{rendered}");
            assert!(rendered.contains("git.example.com"), "{rendered}");
        }

        // The credential kind is still reported, so a log line stays useful.
        assert_eq!(
            token_template.to_string(),
            "https://git.example.com/org (http-token) <- ferriscd-system/token-creds"
        );
        assert!(ssh_template.to_string().contains("(ssh-key)"));

        // Errors carry no value either: the URL in the error is redacted and the keys are named.
        let err = CredentialTemplate::from_secret(&secret(
            "leaky",
            &[
                (KEY_URL, "https://user:hunter2@git.example.com/org"),
                (KEY_PASSWORD, PASSWORD),
            ],
        ))
        .expect_err("embedded credentials must be refused");
        let rendered = format!("{err} {err:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("leaky"), "{rendered}");
    }

    /// **Trap guard (`T12.4`):** a `Secret` in another namespace can never be observed, because
    /// every read is a *namespaced* list. `Debug` never leaks the namespace's payload either.
    ///
    /// (A `kube::Client` needs a Tokio runtime for its buffer worker, hence `#[tokio::test]`.)
    #[tokio::test]
    async fn the_store_is_namespaced_by_construction() {
        let store = SecretCredentialStore::new(offline_client(), "ferriscd-system");
        assert_eq!(store.namespace(), "ferriscd-system");
        assert_eq!(
            SecretCredentialStore::in_control_plane(offline_client()).namespace(),
            CONTROL_PLANE_NAMESPACE
        );
        // Moving the control plane (`--namespace`) moves the credential scope with it: the
        // credentials always live where the `Application`/`AppProject` objects live.
        assert_eq!(
            SecretCredentialStore::new(offline_client(), "apps").namespace(),
            "apps"
        );
        let debug = format!(
            "{:?}",
            SecretCredentialStore::in_control_plane(offline_client())
        );
        assert!(debug.contains("ferriscd-system"), "{debug}");
        assert!(debug.contains(SECRET_TYPE_LABEL), "{debug}");
    }

    // ---------------------------------------------------------------------
    // The wired store (over a recording kube client)
    // ---------------------------------------------------------------------

    /// A `kube::Client` that records the request URIs and answers every call with `body`.
    fn recording_client(body: serde_json::Value) -> (kube::Client, Arc<Mutex<Vec<String>>>) {
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let body = serde_json::to_vec(&body).expect("a serializable body");
        let client = kube::Client::new(
            tower::service_fn(move |request: http::Request<kube::client::Body>| {
                let recorder = recorder.clone();
                let body = body.clone();
                async move {
                    crate::lock_recover(&recorder).push(request.uri().to_string());
                    let response = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(body))
                        .expect("a valid response");
                    Ok::<_, std::convert::Infallible>(response)
                }
            }),
            CONTROL_PLANE_NAMESPACE,
        );
        (client, seen)
    }

    /// A `kube::Client` over a service that never dials out.
    fn offline_client() -> kube::Client {
        recording_client(serde_json::json!({
            "apiVersion": "v1",
            "kind": "SecretList",
            "items": [],
        }))
        .0
    }

    /// Serializes `secrets` into a `SecretList` the API server could have returned.
    fn secret_list(secrets: &[Secret]) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1",
            "kind": "SecretList",
            "metadata": { "resourceVersion": "1" },
            "items": secrets,
        })
    }

    #[tokio::test]
    async fn the_store_lists_only_the_labeled_secrets_of_the_control_plane_namespace() {
        let secrets = vec![secret(
            "creds",
            &[
                (KEY_URL, "https://git.example.com/org/repo"),
                (KEY_TOKEN, TOKEN),
            ],
        )];
        let (client, seen) = recording_client(secret_list(&secrets));
        let store = SecretCredentialStore::in_control_plane(client);

        let credentials = store
            .credentials_for("https://git.example.com/org/repo.git")
            .await
            .expect("the store must resolve the credentials");
        assert_eq!(
            credentials,
            RepoCredentials::HttpToken {
                token: TOKEN.to_owned()
            }
        );

        let requests = crate::lock_recover(&seen).clone();
        assert_eq!(
            requests.len(),
            1,
            "one scoped list per lookup: {requests:?}"
        );
        let request = &requests[0];
        assert!(
            request.starts_with("/api/v1/namespaces/ferriscd-system/secrets"),
            "the read must be namespaced, never cluster-wide: {request}"
        );
        assert!(
            request.contains("labelSelector=ferriscd.io%2Fsecret-type%3Drepository")
                || request.contains("labelSelector=ferriscd.io/secret-type%3Drepository"),
            "the label filter must be sent to the API server: {request}"
        );
    }

    #[tokio::test]
    async fn the_store_returns_anonymous_when_nothing_matches() {
        let secrets = vec![secret(
            "creds",
            &[
                (KEY_URL, "https://git.example.com/org/repo"),
                (KEY_TOKEN, TOKEN),
            ],
        )];
        let (client, _seen) = recording_client(secret_list(&secrets));
        let store = SecretCredentialStore::in_control_plane(client);

        assert_eq!(
            store
                .credentials_for("https://elsewhere.example.com/other")
                .await
                .expect("an unmatched repository is not an error"),
            RepoCredentials::Anonymous
        );
    }

    #[tokio::test]
    async fn an_unusable_secret_reaches_the_pipeline_as_a_terminal_error() {
        let secrets = vec![secret("broken", &[(KEY_TOKEN, TOKEN)])];
        let (client, _seen) = recording_client(secret_list(&secrets));
        let store = SecretCredentialStore::in_control_plane(client);

        let err = store
            .credentials_for("https://git.example.com/org/repo")
            .await
            .expect_err("a Secret without a url must be refused");
        assert!(matches!(&err, ReconcileError::Credentials(_)), "{err:?}");
        assert_eq!(err.failure_class(), crate::FailureClass::Terminal);
        assert!(!err.to_string().contains(TOKEN), "{err}");
    }

    #[tokio::test]
    async fn an_api_failure_is_retryable_and_carries_no_secret() {
        let client = kube::Client::new(
            tower::service_fn(|_request: http::Request<kube::client::Body>| async {
                Ok::<_, std::convert::Infallible>(
                    http::Response::builder()
                        .status(500)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(
                            serde_json::to_vec(&serde_json::json!({
                                "apiVersion": "v1",
                                "kind": "Status",
                                "status": "Failure",
                                "message": "the server is having a bad day",
                                "code": 500,
                            }))
                            .expect("a serializable body"),
                        ))
                        .expect("a valid response"),
                )
            }),
            CONTROL_PLANE_NAMESPACE,
        );
        let store = SecretCredentialStore::in_control_plane(client);
        let err = store
            .credentials_for("https://git.example.com/org/repo")
            .await
            .expect_err("an API failure must not be swallowed");
        assert!(matches!(&err, ReconcileError::Api(_)), "{err:?}");
        assert_eq!(err.failure_class(), crate::FailureClass::Retryable);
    }

    /// The trait object must stay object-safe: the pipeline holds `Arc<dyn CredentialSource>`.
    #[tokio::test]
    async fn the_credential_source_trait_is_object_safe() {
        fn assert_object_safe(_: &dyn CredentialSource) {}
        struct Map;
        impl CredentialSource for Map {
            fn credentials_for<'a>(
                &'a self,
                _repo_url: &'a str,
            ) -> BoxFuture<'a, Result<RepoCredentials, ReconcileError>> {
                Box::pin(async { Ok(RepoCredentials::Anonymous) })
            }
        }
        assert_object_safe(&Map);
        assert_object_safe(&SecretCredentialStore::in_control_plane(offline_client()));
    }

    #[test]
    fn normalization_is_pure_and_rejects_whitespace() {
        assert_eq!(normalize_repo_url("  "), None);
        assert_eq!(normalize_repo_url("https://git.example.com/a b"), None);
        assert_eq!(normalize_repo_url("https://git.example.com/a\nb"), None);
        assert_eq!(
            normalize_repo_url("git@github.com:org/repo.git").as_deref(),
            Some("ssh://github.com/org/repo")
        );
        assert_eq!(
            normalize_repo_url("/tmp/local-repo/").as_deref(),
            Some("/tmp/local-repo")
        );
        // Userinfo never survives normalization, so a normalized URL is always loggable.
        assert_eq!(
            normalize_repo_url("https://user:token@git.example.com/org/repo").as_deref(),
            Some("https://git.example.com/org/repo")
        );
    }
}
