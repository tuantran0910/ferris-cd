//! `gix`-backed implementation of [`super::GitClient`].
//!
//! All `gix` types stay private to this module so the engine API remains
//! completely decoupled from the underlying Git implementation.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use tempfile::TempDir;

use super::auth::AuthContext;
use super::error::RepoError;
use super::sanitize::{WorktreeLimits, sanitize_worktree};
use super::types::{
    GitSource, RepoCheckout, RepoCredentials, RepoUrlPolicy, ResolvedRevision, validate_commit_sha,
};
use super::{GitClient, RepoFuture};

/// Broad refspecs used when querying the full remote ref advertisement.
const ALL_REFS_LIST_SPECS: &[&str] = &[
    "HEAD",
    "+refs/heads/*:refs/remotes/origin/*",
    "+refs/tags/*:refs/tags/*",
];

/// Maximum tag-peeling hops allowed before rejecting a cyclic or pathological tag chain.
const MAX_TAG_PEEL_DEPTH: usize = 64;

/// Configuration for [`GixGitClient`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GixGitClientConfig {
    /// Policy controlling which repository URL schemes are allowed.
    /// Defaults to [`RepoUrlPolicy::Production`].
    pub url_policy: RepoUrlPolicy,
    /// Optional parent directory for temporary bare repositories and checked-out worktrees.
    /// When `None`, the operating system's temporary directory is used.
    pub work_root: Option<PathBuf>,
    /// Permits SSH key credentials without a `known_hosts` entry (**insecure; tests only**).
    ///
    /// Defaults to `false`: production transports MUST verify host keys. With the default, a
    /// missing or whitespace-only `known_hosts` is a terminal
    /// [`RepoError::HostKeyVerificationFailed`] and the generated SSH command pins
    /// `StrictHostKeyChecking=yes`.
    ///
    /// Enabling this flag does two things:
    ///
    /// * a missing `known_hosts` is accepted instead of rejected, and
    /// * the generated command switches to `StrictHostKeyChecking=accept-new`
    ///   (trust-on-first-use), so the connection can actually proceed against a host that is
    ///   not yet known.
    ///
    /// `UserKnownHostsFile=<scratch>/known_hosts` and `BatchMode=yes` are still applied, so the
    /// operator's real `~/.ssh` files are neither read nor written. This flag still removes the
    /// MITM protection that host key verification provides: enable it only in tests or in a
    /// trusted development environment.
    pub allow_missing_known_hosts: bool,
    /// SSH program used for `ssh://` and SCP-style remotes.
    ///
    /// Defaults to `None`, which resolves to `ssh` from `PATH`. The override exists so tests
    /// (and embedded environments) can inject a recording/fake program without mutating the
    /// process-wide `PATH` or `GIT_SSH_COMMAND` environment.
    pub ssh_program: Option<PathBuf>,
    /// Symlink / resource budgets enforced on every materialized worktree before it is
    /// returned. Defaults to [`WorktreeLimits::default`].
    pub worktree_limits: WorktreeLimits,
}

impl GixGitClientConfig {
    /// Creates a new configuration with default settings ([`RepoUrlPolicy::Production`],
    /// system temp directory, strict host key verification, `ssh` from `PATH`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the [`RepoUrlPolicy`] enforced on all incoming [`GitSource`] URLs.
    #[must_use]
    pub fn with_url_policy(mut self, url_policy: RepoUrlPolicy) -> Self {
        self.url_policy = url_policy;
        self
    }

    /// Sets the directory under which temporary scratch bare repos and worktrees are created.
    #[must_use]
    pub fn with_work_root(mut self, work_root: impl Into<PathBuf>) -> Self {
        self.work_root = Some(work_root.into());
        self
    }

    /// Allows SSH key credentials without a `known_hosts` entry (**insecure; tests only**).
    ///
    /// Also downgrades the generated SSH command from `StrictHostKeyChecking=yes` to
    /// `StrictHostKeyChecking=accept-new` (trust-on-first-use) so the connection can proceed;
    /// see [`GixGitClientConfig::allow_missing_known_hosts`].
    #[must_use]
    pub fn with_allow_missing_known_hosts(mut self, allow: bool) -> Self {
        self.allow_missing_known_hosts = allow;
        self
    }

    /// Overrides the SSH program used for SSH remotes (mainly for tests/embedded use).
    #[must_use]
    pub fn with_ssh_program(mut self, ssh_program: impl Into<PathBuf>) -> Self {
        self.ssh_program = Some(ssh_program.into());
        self
    }

    /// Sets the symlink / resource budgets enforced on every materialized worktree.
    #[must_use]
    pub fn with_worktree_limits(mut self, worktree_limits: WorktreeLimits) -> Self {
        self.worktree_limits = worktree_limits;
        self
    }

    /// Snapshot of the owned inputs needed by the blocking layer.
    fn blocking_options(&self) -> BlockingOptions {
        BlockingOptions {
            url_policy: self.url_policy,
            work_root: self.work_root.clone(),
            allow_missing_known_hosts: self.allow_missing_known_hosts,
            ssh_program: self.ssh_program.clone(),
            worktree_limits: self.worktree_limits,
        }
    }
}

/// Owned, `Send + 'static` inputs handed to the blocking worker.
#[derive(Debug, Clone)]
struct BlockingOptions {
    url_policy: RepoUrlPolicy,
    work_root: Option<PathBuf>,
    allow_missing_known_hosts: bool,
    ssh_program: Option<PathBuf>,
    worktree_limits: WorktreeLimits,
}

impl BlockingOptions {
    /// Builds the [`AuthContext`] for one blocking operation.
    ///
    /// Created here (never on a Tokio worker) so the ephemeral SSH key/`known_hosts` file I/O
    /// and zeroization happen on the blocking pool.
    fn auth_context(
        &self,
        url: &gix::Url,
        creds: &RepoCredentials,
    ) -> Result<AuthContext, RepoError> {
        AuthContext::new(
            creds,
            url,
            self.allow_missing_known_hosts,
            self.ssh_program.as_deref(),
        )
    }

    /// Borrows this operation's inputs together with its [`AuthContext`].
    fn context<'a>(&'a self, auth: &'a AuthContext) -> BlockingContext<'a> {
        BlockingContext {
            url_policy: self.url_policy,
            work_root: self.work_root.as_deref(),
            auth,
        }
    }
}

/// Borrowed per-operation context threaded through the blocking helpers.
struct BlockingContext<'a> {
    url_policy: RepoUrlPolicy,
    work_root: Option<&'a Path>,
    auth: &'a AuthContext,
}

/// Pure-Rust `gix`-backed [`GitClient`] implementation supporting local (`file://` / path when
/// permitted by policy), HTTPS (anonymous, bearer token, or basic), and SSH-key repositories.
///
/// Credentials never appear in the clone URL, on-disk `.git/config`, `Debug` output, or error
/// messages: HTTPS identities flow exclusively through the [`gix`] credential callback, and SSH
/// key material is confined to an ephemeral `0600` file inside a [`super::auth::TempKeyGuard`]
/// scratch directory that is zeroized and deleted when the blocking operation ends. See
/// [`super::auth`] for the full transport-hardening design.
#[derive(Debug, Clone, Default)]
pub struct GixGitClient {
    config: GixGitClientConfig,
}

impl GixGitClient {
    /// Creates a new [`GixGitClient`] with the supplied configuration.
    #[must_use]
    pub fn new(config: GixGitClientConfig) -> Self {
        Self { config }
    }

    /// Returns the active client configuration.
    #[must_use]
    pub fn config(&self) -> &GixGitClientConfig {
        &self.config
    }
}

impl GitClient for GixGitClient {
    fn resolve_revision<'a>(
        &'a self,
        src: &'a GitSource,
        creds: &'a RepoCredentials,
    ) -> RepoFuture<'a, ResolvedRevision> {
        Box::pin(async move {
            src.validate(self.config.url_policy)?;

            let url = parse_gix_url(&src.repo_url, self.config.url_policy)?;
            let target_revision = src.target_revision.clone();
            let options = self.config.blocking_options();
            let creds = creds.clone();

            run_blocking("resolve_revision", move || {
                resolve_revision_blocking(url, target_revision, &creds, &options)
            })
            .await
        })
    }

    fn checkout<'a>(
        &'a self,
        src: &'a GitSource,
        sha: &'a str,
        creds: &'a RepoCredentials,
    ) -> RepoFuture<'a, RepoCheckout> {
        Box::pin(async move {
            src.validate(self.config.url_policy)?;
            validate_commit_sha(sha)?;

            let url = parse_gix_url(&src.repo_url, self.config.url_policy)?;
            let target_oid = gix::ObjectId::from_hex(sha.as_bytes()).map_err(|err| {
                RepoError::InvalidRevision {
                    revision: sha.to_owned(),
                    reason: format!("invalid commit SHA '{sha}': {err}"),
                }
            })?;
            let target_revision = src.target_revision.clone();
            let sha_owned = sha.to_owned();
            let options = self.config.blocking_options();
            let creds = creds.clone();

            run_blocking("checkout", move || {
                checkout_blocking(
                    url,
                    target_revision,
                    sha_owned,
                    target_oid,
                    &creds,
                    &options,
                )
            })
            .await
        })
    }
}

async fn run_blocking<F, T>(op_name: &'static str, f: F) -> Result<T, RepoError>
where
    F: FnOnce() -> Result<T, RepoError> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(res) => res,
        Err(join_err) if join_err.is_cancelled() => Err(RepoError::TaskCancelled {
            message: format!("git {op_name} task was cancelled: {join_err}"),
        }),
        Err(join_err) => Err(RepoError::RepositoryError {
            message: format!("git {op_name} worker panicked: {join_err}"),
        }),
    }
}

fn parse_gix_url(raw_url: &str, policy: RepoUrlPolicy) -> Result<gix::Url, RepoError> {
    let normalized: String = if let Some((scheme, rest)) = raw_url.split_once("://") {
        let lower_scheme = scheme.to_ascii_lowercase();
        if lower_scheme == "file" {
            if !matches!(policy, RepoUrlPolicy::AllowLocal) {
                return Err(RepoError::InvalidUrl {
                    url: raw_url.to_owned(),
                    reason: "'file://' URLs are disallowed under production URL policy".to_owned(),
                });
            }
            format!("file://{rest}")
        } else {
            format!("{lower_scheme}://{rest}")
        }
    } else if matches!(policy, RepoUrlPolicy::AllowLocal) && !is_scp_ssh_url(raw_url) {
        // Guard relative local paths containing ':' (e.g. "repo:v1") from gix's SCP detector.
        if !raw_url.starts_with('/') && !raw_url.starts_with("./") && raw_url.contains(':') {
            format!("./{raw_url}")
        } else {
            raw_url.to_owned()
        }
    } else {
        raw_url.to_owned()
    };

    let mut parsed = gix::url::parse(normalized.as_str()).map_err(|err| RepoError::InvalidUrl {
        url: raw_url.to_owned(),
        reason: format!("failed to parse repository URL: {err:#}"),
    })?;

    if parsed.scheme == gix::url::Scheme::File {
        if !matches!(policy, RepoUrlPolicy::AllowLocal) {
            return Err(RepoError::InvalidUrl {
                url: raw_url.to_owned(),
                reason: "local repository URLs are disallowed under production URL policy"
                    .to_owned(),
            });
        }
        if parsed.user().is_some() || parsed.password().is_some() || parsed.port.is_some() {
            return Err(RepoError::InvalidUrl {
                url: raw_url.to_owned(),
                reason: "'file://' URL must not include userinfo or port".to_owned(),
            });
        }
        match parsed.host.as_deref() {
            None => {}
            Some(host) if host.eq_ignore_ascii_case("localhost") => {
                // `gix_transport::client::blocking_io::connect` rejects `host.is_some()` for File,
                // whereas Git treats `file://localhost/path` identically to `file:///path`.
                parsed.host = None;
            }
            Some(host) => {
                return Err(RepoError::InvalidUrl {
                    url: raw_url.to_owned(),
                    reason: format!("'file://' URL host '{host}' is unsupported"),
                });
            }
        }
    }

    Ok(parsed)
}

fn is_scp_ssh_url(url: &str) -> bool {
    url.split_once('@')
        .is_some_and(|(user, after_at)| !user.contains('/') && after_at.contains(':'))
}

fn create_temp_dir(work_root: Option<&Path>) -> Result<TempDir, RepoError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("ferriscd-git-");
    match work_root {
        Some(root) => {
            std::fs::create_dir_all(root).map_err(|source| RepoError::Io {
                context: format!("creating git work_root '{}'", root.display()),
                source,
            })?;
            builder.tempdir_in(root).map_err(|source| RepoError::Io {
                context: format!("creating temp dir under '{}'", root.display()),
                source,
            })
        }
        None => builder.tempdir().map_err(|source| RepoError::Io {
            context: "creating temp dir".to_owned(),
            source,
        }),
    }
}

fn init_isolated_bare_repo(
    dir: &Path,
    ctx: &BlockingContext<'_>,
) -> Result<gix::Repository, RepoError> {
    let mut overrides: Vec<gix::bstr::BString> = vec![
        "protocol.allow=never".into(),
        "protocol.https.allow=always".into(),
        // SSH is a production transport (key + strict host key verification enforced by
        // `AuthContext`), so it is always allowed. `protocol.git://` stays disabled.
        "protocol.ssh.allow=always".into(),
        "http.followRedirects=false".into(),
    ];
    if matches!(ctx.url_policy, RepoUrlPolicy::AllowLocal) {
        overrides.push("protocol.file.allow=always".into());
    }
    // `core.sshCommand` is the configuration equivalent of `GIT_SSH_COMMAND`; applying it as a
    // per-repository override keeps secret key paths out of `.git/config` on disk and out of
    // the process environment.
    overrides.extend(ctx.auth.config_overrides());

    let open_options = gix::open::Options::isolated().config_overrides(overrides);
    gix::ThreadSafeRepository::init_opts(
        dir,
        gix::create::Kind::Bare,
        gix::create::Options::default(),
        open_options,
    )
    .map(Into::into)
    .map_err(map_gix_error)
}

fn open_remote<'repo>(
    repo: &'repo gix::Repository,
    url: gix::Url,
    refspecs: &[&str],
) -> Result<gix::Remote<'repo>, RepoError> {
    repo.remote_at_without_url_rewrite(url)
        .map_err(map_gix_error)?
        .with_fetch_tags(gix::remote::fetch::Tags::None)
        .with_refspecs(refspecs.iter().copied(), gix::remote::Direction::Fetch)
        .map_err(map_gix_error)
}

fn fetch_ref_map(
    repo: &gix::Repository,
    url: gix::Url,
    refspecs: &[&str],
    ctx: &BlockingContext<'_>,
) -> Result<gix::remote::fetch::RefMap, RepoError> {
    let remote = open_remote(repo, url, refspecs)?;
    let connection = remote
        .connect(gix::remote::Direction::Fetch)
        .map_err(map_gix_error)?
        .with_credentials(ctx.auth.credentials_callback());
    let (ref_map, _handshake) = connection
        .ref_map(&mut gix::progress::Discard, Default::default())
        .map_err(map_gix_error)?;
    Ok(ref_map)
}

#[derive(Debug)]
enum FetchStageError {
    /// Failed during connect / handshake / ls-refs (do not mask with fallback).
    ConnectOrRefMap(RepoError),
    /// Remote had no matching refs for the requested explicit refspecs.
    MissingRequiredMapping,
    /// Failed while negotiating or receiving pack objects.
    Receive(RepoError),
}

fn fetch_with_refspecs(
    repo: &gix::Repository,
    url: gix::Url,
    refspecs: &[&str],
    shallow: gix::remote::fetch::Shallow,
    ctx: &BlockingContext<'_>,
) -> Result<(), FetchStageError> {
    let remote = open_remote(repo, url, refspecs).map_err(FetchStageError::ConnectOrRefMap)?;
    let connection = remote
        .connect(gix::remote::Direction::Fetch)
        .map_err(|err| FetchStageError::ConnectOrRefMap(map_gix_error(err)))?
        .with_credentials(ctx.auth.credentials_callback());

    let pending = connection
        .prepare_fetch(&mut gix::progress::Discard, Default::default())
        .map_err(|err| FetchStageError::ConnectOrRefMap(map_gix_error(err)))?;

    if pending.ref_map().is_missing_required_mapping() || pending.ref_map().mappings.is_empty() {
        return Err(FetchStageError::MissingRequiredMapping);
    }

    let should_interrupt = AtomicBool::new(false);
    pending
        .with_shallow(shallow)
        .receive(&mut gix::progress::Discard, &should_interrupt)
        .map(|_| ())
        .map_err(|err| FetchStageError::Receive(map_gix_error(err)))
}

fn resolve_revision_blocking(
    url: gix::Url,
    target_revision: String,
    creds: &RepoCredentials,
    options: &BlockingOptions,
) -> Result<ResolvedRevision, RepoError> {
    let auth = options.auth_context(&url, creds)?;
    let ctx = options.context(&auth);

    let bare_dir = create_temp_dir(ctx.work_root)?;
    let repo = init_isolated_bare_repo(bare_dir.path(), &ctx)?;

    if validate_commit_sha(&target_revision).is_ok() {
        let target_oid = gix::ObjectId::from_hex(target_revision.as_bytes()).map_err(|err| {
            RepoError::InvalidRevision {
                revision: target_revision.clone(),
                reason: format!("invalid commit SHA: {err}"),
            }
        })?;
        return resolve_sha_revision(&repo, url, target_revision, target_oid, &ctx);
    }

    let branch_candidate = format!("refs/heads/{target_revision}");
    let tag_candidate = format!("refs/tags/{target_revision}");
    let refspecs: Vec<&str> = if target_revision == "HEAD" {
        vec!["HEAD"]
    } else if target_revision.starts_with("refs/") {
        vec![target_revision.as_str()]
    } else {
        vec![branch_candidate.as_str(), tag_candidate.as_str()]
    };

    let ref_map = fetch_ref_map(&repo, url.clone(), &refspecs, &ctx)?;
    let matched =
        find_matching_remote_ref(&ref_map.remote_refs, &target_revision).ok_or_else(|| {
            RepoError::RevisionNotFound {
                revision: target_revision.clone(),
            }
        })?;

    let commit_sha = resolve_matched_ref(&repo, url, matched, &target_revision, &ctx)?;
    validate_commit_sha(&commit_sha)?;

    Ok(ResolvedRevision {
        commit_sha,
        requested_ref: target_revision,
    })
}

fn find_matching_remote_ref<'a>(
    remote_refs: &'a [gix::protocol::handshake::Ref],
    target_revision: &str,
) -> Option<&'a gix::protocol::handshake::Ref> {
    use gix::bstr::ByteSlice;

    let find_exact = |name: &str| {
        remote_refs
            .iter()
            .find(|r| r.unpack().0 == name.as_bytes().as_bstr())
    };

    if target_revision == "HEAD" || target_revision.starts_with("refs/") {
        find_exact(target_revision)
    } else {
        find_exact(&format!("refs/heads/{target_revision}"))
            .or_else(|| find_exact(&format!("refs/tags/{target_revision}")))
    }
}

fn validate_resolved_oid(
    oid: gix::ObjectId,
    requested_revision: &str,
) -> Result<String, RepoError> {
    if oid.is_null() {
        return Err(RepoError::RevisionNotFound {
            revision: requested_revision.to_owned(),
        });
    }
    let sha = oid.to_string();
    validate_commit_sha(&sha)?;
    Ok(sha)
}

fn resolve_matched_ref(
    repo: &gix::Repository,
    url: gix::Url,
    matched: &gix::protocol::handshake::Ref,
    requested_revision: &str,
    ctx: &BlockingContext<'_>,
) -> Result<String, RepoError> {
    use gix::bstr::ByteSlice;
    use gix::protocol::handshake::Ref;

    match matched {
        Ref::Unborn { .. } => Err(RepoError::RevisionNotFound {
            revision: requested_revision.to_owned(),
        }),
        Ref::Direct {
            full_ref_name,
            object,
        } => {
            if full_ref_name.starts_with(b"refs/heads/") {
                validate_resolved_oid(*object, requested_revision)
            } else {
                // Tags (lightweight or unpeeled annotated) or custom refs: fetch and peel to commit.
                let ref_name = full_ref_name
                    .to_str()
                    .map_err(|_| RepoError::RepositoryError {
                        message: format!(
                            "remote ref name for '{requested_revision}' is not valid UTF-8"
                        ),
                    })?;
                fetch_ref_and_peel_to_commit(repo, url, ref_name, *object, requested_revision, ctx)
            }
        }
        Ref::Symbolic {
            full_ref_name,
            target,
            tag,
            object,
        } => {
            if tag.is_none()
                && (full_ref_name == "HEAD" || full_ref_name.starts_with(b"refs/heads/"))
                && target.starts_with(b"refs/heads/")
            {
                validate_resolved_oid(*object, requested_revision)
            } else {
                let ref_name = full_ref_name
                    .to_str()
                    .map_err(|_| RepoError::RepositoryError {
                        message: format!(
                            "remote ref name for '{requested_revision}' is not valid UTF-8"
                        ),
                    })?;
                let start_oid = tag.unwrap_or(*object);
                fetch_ref_and_peel_to_commit(
                    repo,
                    url,
                    ref_name,
                    start_oid,
                    requested_revision,
                    ctx,
                )
            }
        }
        Ref::Peeled {
            full_ref_name,
            tag,
            object: _,
        } => {
            // `tag` is the tag object OID and `object` is the server-peeled target.
            // Fetch the tag object and peel locally so nested annotated tags are fully peeled
            // and tags pointing to blobs/trees are rejected cleanly.
            let ref_name = full_ref_name
                .to_str()
                .map_err(|_| RepoError::RepositoryError {
                    message: format!(
                        "remote ref name for '{requested_revision}' is not valid UTF-8"
                    ),
                })?;
            fetch_ref_and_peel_to_commit(repo, url, ref_name, *tag, requested_revision, ctx)
        }
    }
}

fn fetch_ref_with_shallow_fallback(
    repo: &gix::Repository,
    url: gix::Url,
    ref_name: &str,
    requested_revision: &str,
    ctx: &BlockingContext<'_>,
) -> Result<Option<(TempDir, gix::Repository)>, RepoError> {
    let shallow = gix::remote::fetch::Shallow::DepthAtRemote(NonZeroU32::MIN);
    match fetch_with_refspecs(repo, url.clone(), &[ref_name], shallow, ctx) {
        Ok(()) => Ok(None),
        Err(FetchStageError::ConnectOrRefMap(err)) => Err(err),
        Err(FetchStageError::MissingRequiredMapping) => Err(RepoError::RevisionNotFound {
            revision: requested_revision.to_owned(),
        }),
        Err(FetchStageError::Receive(err)) => {
            if is_fatal_without_fallback(&err) {
                return Err(err);
            }
            // Some servers reject `deepen 1` on non-commit targets (e.g. tag -> blob/tree);
            // fall back on a clean bare repo with `Shallow::NoChange` so we can inspect the object kind.
            let fallback_dir = create_temp_dir(ctx.work_root)?;
            let fallback_repo = init_isolated_bare_repo(fallback_dir.path(), ctx)?;
            fetch_with_refspecs(
                &fallback_repo,
                url,
                &[ref_name],
                gix::remote::fetch::Shallow::NoChange,
                ctx,
            )
            .map_err(fetch_stage_error_into_repo_error(requested_revision))?;
            Ok(Some((fallback_dir, fallback_repo)))
        }
    }
}

fn fetch_ref_and_peel_to_commit(
    repo: &gix::Repository,
    url: gix::Url,
    ref_name: &str,
    start_oid: gix::ObjectId,
    requested_revision: &str,
    ctx: &BlockingContext<'_>,
) -> Result<String, RepoError> {
    let fallback = fetch_ref_with_shallow_fallback(repo, url, ref_name, requested_revision, ctx)?;
    let active_repo = fallback.as_ref().map_or(repo, |(_, r)| r);
    peel_local_object_to_commit(active_repo, start_oid, requested_revision)
}

fn fetch_ref_and_verify_exact_commit(
    repo: &gix::Repository,
    url: gix::Url,
    ref_name: &str,
    target_oid: gix::ObjectId,
    requested_revision: &str,
    ctx: &BlockingContext<'_>,
) -> Result<String, RepoError> {
    let fallback = fetch_ref_with_shallow_fallback(repo, url, ref_name, requested_revision, ctx)?;
    let active_repo = fallback.as_ref().map_or(repo, |(_, r)| r);
    verify_local_commit(active_repo, target_oid, requested_revision)?;
    Ok(requested_revision.to_owned())
}

fn peel_local_object_to_commit(
    repo: &gix::Repository,
    start_oid: gix::ObjectId,
    requested_revision: &str,
) -> Result<String, RepoError> {
    let mut current_id = start_oid;
    for _ in 0..MAX_TAG_PEEL_DEPTH {
        let Some(obj) = repo.try_find_object(current_id).map_err(map_gix_error)? else {
            return Err(RepoError::RevisionNotFound {
                revision: requested_revision.to_owned(),
            });
        };
        match obj.kind {
            gix::object::Kind::Commit => {
                return validate_resolved_oid(obj.id, requested_revision);
            }
            gix::object::Kind::Tag => {
                let tag = obj.try_into_tag().map_err(map_gix_error)?;
                let target_id = tag.target_id().map_err(map_gix_error)?.detach();
                current_id = target_id;
            }
            other @ (gix::object::Kind::Tree | gix::object::Kind::Blob) => {
                return Err(RepoError::InvalidRevision {
                    revision: requested_revision.to_owned(),
                    reason: format!("expected commit object, found {other}"),
                });
            }
        }
    }

    Err(RepoError::InvalidRevision {
        revision: requested_revision.to_owned(),
        reason: "tag peeling depth limit exceeded".to_owned(),
    })
}

fn resolve_sha_revision(
    repo: &gix::Repository,
    url: gix::Url,
    target_revision: String,
    target_oid: gix::ObjectId,
    ctx: &BlockingContext<'_>,
) -> Result<ResolvedRevision, RepoError> {
    use gix::bstr::ByteSlice;
    use gix::protocol::handshake::Ref;

    let ref_map = fetch_ref_map(repo, url.clone(), ALL_REFS_LIST_SPECS, ctx)?;
    if target_oid.is_null() {
        return Err(RepoError::RevisionNotFound {
            revision: target_revision,
        });
    }

    for remote_ref in &ref_map.remote_refs {
        match remote_ref {
            Ref::Peeled {
                full_ref_name,
                tag,
                object,
            } => {
                if *tag == target_oid {
                    return Err(RepoError::InvalidRevision {
                        revision: target_revision,
                        reason: "revision refers to an annotated tag object, not a commit"
                            .to_owned(),
                    });
                }
                if *object == target_oid {
                    let ref_name =
                        full_ref_name
                            .to_str()
                            .map_err(|_| RepoError::RepositoryError {
                                message: "advertised remote ref name is not valid UTF-8".to_owned(),
                            })?;
                    let sha = fetch_ref_and_verify_exact_commit(
                        repo,
                        url,
                        ref_name,
                        *object,
                        &target_revision,
                        ctx,
                    )?;
                    return Ok(ResolvedRevision {
                        commit_sha: sha,
                        requested_ref: target_revision,
                    });
                }
            }
            Ref::Direct {
                full_ref_name,
                object,
            } if *object == target_oid => {
                if full_ref_name.starts_with(b"refs/heads/") {
                    return Ok(ResolvedRevision {
                        commit_sha: target_revision.clone(),
                        requested_ref: target_revision,
                    });
                }
                let ref_name = full_ref_name
                    .to_str()
                    .map_err(|_| RepoError::RepositoryError {
                        message: "advertised remote ref name is not valid UTF-8".to_owned(),
                    })?;
                let sha = fetch_ref_and_verify_exact_commit(
                    repo,
                    url,
                    ref_name,
                    *object,
                    &target_revision,
                    ctx,
                )?;
                return Ok(ResolvedRevision {
                    commit_sha: sha,
                    requested_ref: target_revision,
                });
            }
            Ref::Symbolic {
                full_ref_name,
                target,
                tag,
                object,
            } => {
                if tag.as_ref() == Some(&target_oid) {
                    return Err(RepoError::InvalidRevision {
                        revision: target_revision,
                        reason: "revision refers to an annotated tag object, not a commit"
                            .to_owned(),
                    });
                }
                if *object == target_oid {
                    if tag.is_none() && target.starts_with(b"refs/heads/") {
                        return Ok(ResolvedRevision {
                            commit_sha: target_revision.clone(),
                            requested_ref: target_revision,
                        });
                    }
                    let ref_name =
                        full_ref_name
                            .to_str()
                            .map_err(|_| RepoError::RepositoryError {
                                message: "advertised remote ref name is not valid UTF-8".to_owned(),
                            })?;
                    let sha = fetch_ref_and_verify_exact_commit(
                        repo,
                        url,
                        ref_name,
                        *object,
                        &target_revision,
                        ctx,
                    )?;
                    return Ok(ResolvedRevision {
                        commit_sha: sha,
                        requested_ref: target_revision,
                    });
                }
            }
            _ => {}
        }
    }

    // Historical SHA path: try shallow fetch of the SHA first, then fall back to full fetch.
    let (_active_dir, active_repo) = fetch_sha_shallow_then_fallback(
        url,
        &target_revision,
        &target_revision,
        &[target_revision.as_str()],
        target_oid,
        ctx,
    )?;

    verify_local_commit(&active_repo, target_oid, &target_revision)?;
    Ok(ResolvedRevision {
        commit_sha: target_revision.clone(),
        requested_ref: target_revision,
    })
}

fn checkout_blocking(
    url: gix::Url,
    target_revision: String,
    sha: String,
    target_oid: gix::ObjectId,
    creds: &RepoCredentials,
    options: &BlockingOptions,
) -> Result<RepoCheckout, RepoError> {
    let auth = options.auth_context(&url, creds)?;
    let ctx = options.context(&auth);

    if target_oid.is_null() {
        return Err(RepoError::RevisionNotFound { revision: sha });
    }

    let branch_candidate = format!("refs/heads/{target_revision}");
    let tag_candidate = format!("refs/tags/{target_revision}");
    let shallow_refspecs: Vec<&str> = if validate_commit_sha(&target_revision).is_ok() {
        vec![sha.as_str()]
    } else if target_revision == "HEAD" {
        vec!["HEAD"]
    } else if target_revision.starts_with("refs/") {
        vec![target_revision.as_str()]
    } else {
        vec![branch_candidate.as_str(), tag_candidate.as_str()]
    };

    let (_bare_dir, active_repo) = fetch_sha_shallow_then_fallback(
        url,
        &target_revision,
        &sha,
        &shallow_refspecs,
        target_oid,
        &ctx,
    )?;

    let root_tree_id = verify_local_commit(&active_repo, target_oid, &sha)?;
    let checkout_dir = materialize_commit_worktree(&active_repo, root_tree_id, ctx.work_root)?;
    let checkout_path = checkout_dir.path().to_path_buf();

    // Defend every renderer (Plain YAML, Kustomize, Helm) against symlink escapes by
    // sanitizing the materialized worktree before handing it back. This runs on the blocking
    // pool; on failure the `TempDir` checkout lease is dropped, deleting the worktree.
    sanitize_worktree(&checkout_path, &options.worktree_limits)?;

    Ok(RepoCheckout::with_lease(
        checkout_path,
        sha,
        Arc::new(checkout_dir),
    ))
}

fn build_fallback_refspecs(target_revision: &str) -> Vec<String> {
    let mut specs = vec![
        "+refs/heads/*:refs/remotes/origin/*".to_owned(),
        "+refs/tags/*:refs/tags/*".to_owned(),
    ];
    if target_revision == "HEAD" || validate_commit_sha(target_revision).is_ok() {
        specs.push("HEAD:refs/remotes/origin/HEAD".to_owned());
    } else if target_revision.starts_with("refs/")
        && !target_revision.starts_with("refs/heads/")
        && !target_revision.starts_with("refs/tags/")
    {
        specs.push(format!(
            "+{target_revision}:refs/remotes/origin/custom-target"
        ));
    }
    specs
}

/// Attempts a shallow (`depth = 1`) fetch using `shallow_refspecs`, returning the active bare
/// repository handle containing `target_oid`. If the shallow fetch fails with a non-fatal error
/// or does not bring in `target_oid`, creates a fresh isolated bare repository and performs a full
/// fallback fetch (`Shallow::NoChange`) across branches, tags, and `target_revision` (when `HEAD`
/// or a custom ref).
fn fetch_sha_shallow_then_fallback(
    url: gix::Url,
    target_revision: &str,
    revision_label: &str,
    shallow_refspecs: &[&str],
    target_oid: gix::ObjectId,
    ctx: &BlockingContext<'_>,
) -> Result<(TempDir, gix::Repository), RepoError> {
    let shallow_dir = create_temp_dir(ctx.work_root)?;
    let shallow_repo = init_isolated_bare_repo(shallow_dir.path(), ctx)?;

    match fetch_with_refspecs(
        &shallow_repo,
        url.clone(),
        shallow_refspecs,
        gix::remote::fetch::Shallow::DepthAtRemote(NonZeroU32::MIN),
        ctx,
    ) {
        Ok(()) => {
            if shallow_repo
                .try_find_object(target_oid)
                .map_err(map_gix_error)?
                .is_some()
            {
                return Ok((shallow_dir, shallow_repo));
            }
        }
        Err(FetchStageError::ConnectOrRefMap(err)) => return Err(err),
        // A server rejecting an unadvertised SHA-in-want may close the pipe mid-request
        // (racy "Broken pipe"); treat that as a recoverable shallow failure, not fatal.
        Err(FetchStageError::Receive(err))
            if is_fatal_without_fallback(&err) && !is_broken_pipe_network_error(&err) =>
        {
            return Err(err);
        }
        Err(FetchStageError::MissingRequiredMapping | FetchStageError::Receive(_)) => {}
    }

    // Drop the shallow repo before fallback so its `.git/shallow` boundary cannot suppress ancestors.
    drop(shallow_repo);
    drop(shallow_dir);

    let fallback_dir = create_temp_dir(ctx.work_root)?;
    let fallback_repo = init_isolated_bare_repo(fallback_dir.path(), ctx)?;
    let fallback_specs = build_fallback_refspecs(target_revision);
    let fallback_spec_refs: Vec<&str> = fallback_specs.iter().map(String::as_str).collect();
    fetch_with_refspecs(
        &fallback_repo,
        url,
        &fallback_spec_refs,
        gix::remote::fetch::Shallow::NoChange,
        ctx,
    )
    .map_err(fetch_stage_error_into_repo_error(revision_label))?;

    Ok((fallback_dir, fallback_repo))
}

fn fetch_stage_error_into_repo_error(
    revision_label: &str,
) -> impl FnOnce(FetchStageError) -> RepoError + '_ {
    move |err| match err {
        FetchStageError::ConnectOrRefMap(e) | FetchStageError::Receive(e) => e,
        FetchStageError::MissingRequiredMapping => RepoError::RevisionNotFound {
            revision: revision_label.to_owned(),
        },
    }
}

fn verify_local_commit(
    repo: &gix::Repository,
    target_oid: gix::ObjectId,
    revision_label: &str,
) -> Result<gix::ObjectId, RepoError> {
    let Some(obj) = repo.try_find_object(target_oid).map_err(map_gix_error)? else {
        return Err(RepoError::RevisionNotFound {
            revision: revision_label.to_owned(),
        });
    };

    if obj.kind != gix::object::Kind::Commit {
        return Err(RepoError::InvalidRevision {
            revision: revision_label.to_owned(),
            reason: format!("expected commit object, found {}", obj.kind),
        });
    }

    let commit = obj.try_into_commit().map_err(map_gix_error)?;
    let tree_id = commit.tree_id().map_err(map_gix_error)?.detach();
    Ok(tree_id)
}

fn materialize_commit_worktree(
    repo: &gix::Repository,
    root_tree_id: gix::ObjectId,
    work_root: Option<&Path>,
) -> Result<TempDir, RepoError> {
    let mut index = repo.index_from_tree(&root_tree_id).map_err(map_gix_error)?;
    let mut opts = repo
        .checkout_options(gix::worktree::stack::state::attributes::Source::IdMapping)
        .map_err(map_gix_error)?;
    opts.destination_is_initially_empty = true;
    opts.overwrite_existing = false;
    opts.keep_going = false;

    let checkout_dir = create_temp_dir(work_root)?;
    let should_interrupt = AtomicBool::new(false);
    let objects = repo
        .objects
        .clone()
        .into_arc()
        .map_err(|err| RepoError::RepositoryError {
            message: format!("failed to create shared ODB handle for checkout: {err}"),
        })?;

    let outcome = gix::worktree::state::checkout(
        &mut index,
        checkout_dir.path(),
        objects,
        &gix::progress::Discard,
        &gix::progress::Discard,
        &should_interrupt,
        opts,
    )
    .map_err(map_gix_error)?;

    if let Some(first_err) = outcome.errors.into_iter().next() {
        return Err(map_gix_error(first_err.error));
    }
    if let Some(collision) = outcome.collisions.into_iter().next() {
        return Err(RepoError::RepositoryError {
            message: format!(
                "checkout path collision at '{}': {}",
                collision.path, collision.error_kind
            ),
        });
    }

    Ok(checkout_dir)
}

fn is_broken_pipe_network_error(err: &RepoError) -> bool {
    matches!(err, RepoError::Network { message } if message.contains("Broken pipe"))
}

fn is_fatal_without_fallback(err: &RepoError) -> bool {
    matches!(
        err,
        RepoError::InvalidUrl { .. }
            | RepoError::InvalidSource { .. }
            | RepoError::InvalidRevision { .. }
            | RepoError::AuthFailed { .. }
            | RepoError::HostKeyVerificationFailed { .. }
            | RepoError::TaskCancelled { .. }
            | RepoError::Network { .. }
            | RepoError::Timeout { .. }
            | RepoError::RemoteServerError {
                status: Some(_),
                ..
            }
    )
}

fn format_gix_error_chain(err: &gix::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in err.iter_errors() {
        let text = cause.to_string();
        if !text.is_empty() && parts.last() != Some(&text) {
            parts.push(text);
        }
    }
    if parts.is_empty() {
        err.to_string()
    } else {
        parts.join(": ")
    }
}

fn map_gix_error(err: gix::Error) -> RepoError {
    use gix::protocol::transport::{client, packetline};

    let full_message = format_gix_error_chain(&err);

    if err.is_cancelled() {
        return RepoError::TaskCancelled {
            message: full_message,
        };
    }

    if err.is_unauthenticated()
        || err
            .downcast_any_ref::<client::AuthenticationRequired>()
            .is_some()
    {
        return RepoError::AuthFailed {
            reason: full_message,
        };
    }

    if let Some(status) = extract_http_status(&err) {
        return match status {
            401 | 403 => RepoError::AuthFailed {
                reason: full_message,
            },
            _ => RepoError::RemoteServerError {
                status: Some(status),
                message: full_message,
            },
        };
    }

    let mut is_http_transport = false;
    for cause in err.iter_errors() {
        if let Some(transport_err) = cause.downcast_ref::<client::Error>() {
            match transport_err {
                client::Error::AuthenticationUnsupported
                | client::Error::AuthenticationRefused(_) => {
                    return RepoError::AuthFailed {
                        reason: full_message,
                    };
                }
                client::Error::Http(_) => {
                    is_http_transport = true;
                }
                client::Error::UnsupportedProtocolVersion(_)
                | client::Error::AmbiguousPath { .. }
                | client::Error::MissingHandshake
                | client::Error::Capabilities { .. }
                | client::Error::LineDecode { .. }
                | client::Error::ExpectedLine(_)
                | client::Error::ExpectedDataLine => {
                    return RepoError::RepositoryError {
                        message: full_message,
                    };
                }
                client::Error::InvokeProgram { .. } | client::Error::SshInvocation(_) => {
                    return RepoError::RepositoryError {
                        message: full_message,
                    };
                }
                client::Error::Io(_) => {}
            }
        }
    }

    if err.is_permission_denied() {
        return RepoError::AuthFailed {
            reason: full_message,
        };
    }

    if let Some(pkt_err) = err.downcast_any_ref::<packetline::read::Error>() {
        let lower = pkt_err.message.to_string().to_ascii_lowercase();
        if lower.contains("authentication")
            || lower.contains("unauthorized")
            || lower.contains("permission denied")
            || lower.contains("access denied")
        {
            return RepoError::AuthFailed {
                reason: full_message,
            };
        }
        return RepoError::RepositoryError {
            message: full_message,
        };
    }

    if contains_timeout_hint(&err, &full_message) {
        return RepoError::Timeout {
            message: full_message,
        };
    }

    if err.is_retryable() || err.can_retry() {
        return RepoError::Network {
            message: full_message,
        };
    }

    if let Some(io_err) = err
        .iter_errors()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
    {
        return classify_io_error(io_err, is_http_transport, &full_message);
    }

    if is_http_transport {
        return RepoError::Network {
            message: full_message,
        };
    }

    if err.is_not_found() || err.is_validation() || err.is_corrupted() || err.is_unsupported() {
        return RepoError::RepositoryError {
            message: full_message,
        };
    }

    RepoError::RepositoryError {
        message: full_message,
    }
}

fn extract_http_status(err: &gix::Error) -> Option<u16> {
    const PREFIX: &str = "Received HTTP status ";
    for cause in err.iter_errors() {
        let text = cause.to_string();
        if let Some(rest) = text.strip_prefix(PREFIX) {
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(code) = digits.parse::<u16>() {
                return Some(code);
            }
        }
    }
    None
}

fn contains_timeout_hint(err: &gix::Error, full_message: &str) -> bool {
    let io_timed_out = err.iter_errors().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::TimedOut)
    });
    if io_timed_out {
        return true;
    }
    let lower = full_message.to_ascii_lowercase();
    lower.contains("timed out") || lower.contains("operation timeout")
}

fn classify_io_error(
    io_err: &std::io::Error,
    is_http_transport: bool,
    full_message: &str,
) -> RepoError {
    use std::io::ErrorKind;

    match io_err.kind() {
        ErrorKind::TimedOut => RepoError::Timeout {
            message: full_message.to_owned(),
        },
        ErrorKind::ConnectionRefused
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted
        | ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe
        | ErrorKind::AddrInUse
        | ErrorKind::AddrNotAvailable
        | ErrorKind::NotConnected
        | ErrorKind::NetworkUnreachable
        | ErrorKind::HostUnreachable => RepoError::Network {
            message: full_message.to_owned(),
        },
        ErrorKind::NotFound => RepoError::RepositoryError {
            message: full_message.to_owned(),
        },
        ErrorKind::PermissionDenied => RepoError::AuthFailed {
            reason: full_message.to_owned(),
        },
        _ if is_http_transport => RepoError::Network {
            message: full_message.to_owned(),
        },
        ErrorKind::InvalidData | ErrorKind::InvalidInput | ErrorKind::IsADirectory => {
            RepoError::RepositoryError {
                message: full_message.to_owned(),
            }
        }
        kind => RepoError::Io {
            context: full_message.to_owned(),
            source: std::io::Error::new(kind, io_err.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::process::Command;

    use super::*;

    struct TestRepoFixture {
        _root: TempDir,
        work_path: PathBuf,
        bare_path: PathBuf,
        c1: String,
        c2: String,
        c3: String,
        c_rel: String,
        v1_tag_oid: String,
        nested_tag_oid: String,
        blob_oid: String,
        tree_oid: String,
        blob_tag_name: String,
        tree_tag_name: String,
        light_to_annotated_tag: String,
    }

    fn git_cmd(cwd: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Ferris Test")
            .env("GIT_AUTHOR_EMAIL", "ferris@example.com")
            .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
            .env("GIT_COMMITTER_NAME", "Ferris Test")
            .env("GIT_COMMITTER_EMAIL", "ferris@example.com")
            .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
            .output()
            .expect("git command should execute");
        assert!(
            output.status.success(),
            "git {:?} failed (cwd={}): stdout={}, stderr={}",
            args,
            cwd.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    fn build_fixture() -> TestRepoFixture {
        let root = tempfile::tempdir().expect("create fixture temp dir");
        let work = root.path().join("work");
        let bare = root.path().join("remote.git");
        std::fs::create_dir_all(&work).expect("create work dir");

        git_cmd(&work, &["init", "--initial-branch=main"]);

        // c1: initial commit + lightweight tag v1.0.0-light
        std::fs::create_dir_all(work.join("apps/base")).expect("mkdir apps/base");
        std::fs::write(work.join("README.md"), "version=c1\n").expect("write README");
        std::fs::write(
            work.join("apps/base/deployment.yaml"),
            "kind: Deployment\nmetadata:\n  name: app-c1\n",
        )
        .expect("write c1 deployment");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "commit c1"]);
        let c1 = git_cmd(&work, &["rev-parse", "HEAD"]);
        let blob_oid = git_cmd(&work, &["rev-parse", "HEAD:README.md"]);
        let tree_oid = git_cmd(&work, &["rev-parse", "HEAD^{tree}"]);
        git_cmd(&work, &["tag", "v1.0.0-light", &c1]);

        // c2: update README + add extra file + annotated tag v1.0.0 + nested annotated tag v1.0.0-nested
        std::fs::create_dir_all(work.join("apps/overlays/prod")).expect("mkdir overlays");
        std::fs::write(work.join("README.md"), "version=c2\n").expect("write README c2");
        std::fs::write(
            work.join("apps/overlays/prod/kustomization.yaml"),
            "resources: []\n",
        )
        .expect("write kustomization");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "commit c2"]);
        let c2 = git_cmd(&work, &["rev-parse", "HEAD"]);
        git_cmd(&work, &["tag", "-a", "v1.0.0", "-m", "Release v1.0.0", &c2]);
        let v1_tag_oid = git_cmd(&work, &["rev-parse", "v1.0.0"]);
        git_cmd(
            &work,
            &[
                "tag",
                "-a",
                "v1.0.0-nested",
                "-m",
                "Nested tag",
                &v1_tag_oid,
            ],
        );
        let nested_tag_oid = git_cmd(&work, &["rev-parse", "v1.0.0-nested"]);

        // Annotated tag pointing directly to a blob (non-commit!)
        let blob_tag_name = "blob-tag".to_owned();
        git_cmd(
            &work,
            &["tag", "-a", &blob_tag_name, "-m", "Tag to blob", &blob_oid],
        );
        // Annotated tag pointing directly to a tree (non-commit!)
        let tree_tag_name = "tree-tag".to_owned();
        git_cmd(
            &work,
            &["tag", "-a", &tree_tag_name, "-m", "Tag to tree", &tree_oid],
        );
        // Lightweight tag pointing directly to an annotated tag (must peel to c2)
        let light_to_annotated_tag = "light-to-annotated".to_owned();
        git_cmd(&work, &["tag", &light_to_annotated_tag, &v1_tag_oid]);

        // c3: tip of main
        std::fs::write(work.join("README.md"), "version=c3\n").expect("write README c3");
        std::fs::write(work.join("CHANGELOG.md"), "c3 changes\n").expect("write CHANGELOG");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "commit c3"]);
        let c3 = git_cmd(&work, &["rev-parse", "HEAD"]);

        // Second branch release/v2 branching off c2
        git_cmd(&work, &["checkout", "-b", "release/v2", &c2]);
        std::fs::write(work.join("README.md"), "version=release-v2\n").expect("write README rel");
        std::fs::write(work.join("RELEASE_NOTES.md"), "v2\n").expect("write release notes");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "commit release/v2"]);
        let c_rel = git_cmd(&work, &["rev-parse", "HEAD"]);

        // Switch back to main before cloning bare
        git_cmd(&work, &["checkout", "main"]);
        git_cmd(
            root.path(),
            &[
                "clone",
                "--bare",
                work.to_str().expect("utf8 path"),
                bare.to_str().expect("utf8 path"),
            ],
        );
        // Ensure default bare repo does NOT enable arbitrary SHA-in-want (tests fallback path!)
        git_cmd(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);

        TestRepoFixture {
            _root: root,
            work_path: work,
            bare_path: bare,
            c1,
            c2,
            c3,
            c_rel,
            v1_tag_oid,
            nested_tag_oid,
            blob_oid,
            tree_oid,
            blob_tag_name,
            tree_tag_name,
            light_to_annotated_tag,
        }
    }

    fn local_client(work_root: Option<PathBuf>) -> GixGitClient {
        let mut cfg = GixGitClientConfig::new().with_url_policy(RepoUrlPolicy::AllowLocal);
        if let Some(root) = work_root {
            cfg = cfg.with_work_root(root);
        }
        GixGitClient::new(cfg)
    }

    /// Credential-free [`AuthContext`] for tests that only exercise repo plumbing.
    fn anonymous_auth() -> AuthContext {
        let url = gix::url::parse(b"https://example.invalid/org/repo.git".as_slice())
            .expect("valid https url");
        AuthContext::new(&RepoCredentials::Anonymous, &url, false, None).expect("anonymous auth")
    }

    /// Borrowed [`BlockingContext`] around `auth` for direct helper tests.
    fn blocking_ctx<'a>(auth: &'a AuthContext, url_policy: RepoUrlPolicy) -> BlockingContext<'a> {
        BlockingContext {
            url_policy,
            work_root: None,
            auth,
        }
    }

    fn snapshot_tree(root: &Path) -> BTreeMap<String, String> {
        fn walk(base: &Path, cur: &Path, out: &mut BTreeMap<String, String>) {
            for entry in std::fs::read_dir(cur).expect("read dir") {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .expect("strip prefix")
                    .to_string_lossy()
                    .replace('\\', "/");
                if entry.file_type().expect("file type").is_dir() {
                    walk(base, &path, out);
                } else {
                    let body = std::fs::read_to_string(&path).expect("read utf8 file");
                    out.insert(rel, body);
                }
            }
        }
        let mut map = BTreeMap::new();
        walk(root, root, &mut map);
        map
    }

    #[tokio::test]
    async fn resolve_and_checkout_head_and_branches() {
        let fx = build_fixture();
        let client: Arc<dyn GitClient> = Arc::new(local_client(None));
        let repo_str = fx.bare_path.to_str().expect("utf8 path");
        let creds = RepoCredentials::Anonymous;

        // 1. HEAD -> c3
        let head_src = GitSource::new(repo_str, "HEAD", "");
        let resolved = client
            .resolve_revision(&head_src, &creds)
            .await
            .expect("resolve HEAD");
        assert_eq!(resolved.commit_sha, fx.c3);
        assert_eq!(resolved.requested_ref, "HEAD");

        let co = client
            .checkout(&head_src, &resolved.commit_sha, &creds)
            .await
            .expect("checkout HEAD");
        assert_eq!(co.commit_sha(), fx.c3);
        assert!(
            !co.root_dir().join(".git").exists(),
            "worktree must not contain .git"
        );
        let tree = snapshot_tree(co.root_dir());
        assert_eq!(
            tree.get("README.md").map(String::as_str),
            Some("version=c3\n")
        );
        assert_eq!(
            tree.get("CHANGELOG.md").map(String::as_str),
            Some("c3 changes\n")
        );
        assert!(tree.contains_key("apps/base/deployment.yaml"));
        assert!(tree.contains_key("apps/overlays/prod/kustomization.yaml"));

        // 2. main -> c3
        let main_src = GitSource::new(repo_str, "main", "");
        let resolved_main = client
            .resolve_revision(&main_src, &creds)
            .await
            .expect("resolve main");
        assert_eq!(resolved_main.commit_sha, fx.c3);

        // 3. release/v2 and explicit refs/heads/release/v2 -> c_rel
        for rev in ["release/v2", "refs/heads/release/v2"] {
            let rel_src = GitSource::new(repo_str, rev, "");
            let res_rel = client
                .resolve_revision(&rel_src, &creds)
                .await
                .expect("resolve release/v2");
            assert_eq!(res_rel.commit_sha, fx.c_rel);
            assert_eq!(res_rel.requested_ref, rev);

            let co_rel = client
                .checkout(&rel_src, &res_rel.commit_sha, &creds)
                .await
                .expect("checkout release/v2");
            let rel_tree = snapshot_tree(co_rel.root_dir());
            assert_eq!(
                rel_tree.get("README.md").map(String::as_str),
                Some("version=release-v2\n")
            );
            assert_eq!(
                rel_tree.get("RELEASE_NOTES.md").map(String::as_str),
                Some("v2\n")
            );
            assert!(!rel_tree.contains_key("CHANGELOG.md"));
        }
    }

    #[tokio::test]
    async fn resolve_and_checkout_lightweight_annotated_and_nested_tags() {
        let fx = build_fixture();
        let client = local_client(None);
        let repo_str = fx.bare_path.to_str().expect("utf8 path");
        let creds = RepoCredentials::Anonymous;

        // 3. Lightweight tag -> c1
        for rev in ["v1.0.0-light", "refs/tags/v1.0.0-light"] {
            let src = GitSource::new(repo_str, rev, "");
            let res = client
                .resolve_revision(&src, &creds)
                .await
                .expect("resolve lightweight tag");
            assert_eq!(res.commit_sha, fx.c1);
            let co = client
                .checkout(&src, &res.commit_sha, &creds)
                .await
                .expect("checkout lightweight tag");
            let tree = snapshot_tree(co.root_dir());
            assert_eq!(
                tree.get("README.md").map(String::as_str),
                Some("version=c1\n")
            );
            assert!(!tree.contains_key("CHANGELOG.md"));
            assert!(!tree.contains_key("apps/overlays/prod/kustomization.yaml"));
        }

        // 4. Annotated tag -> c2 (must NOT equal tag OID!)
        assert_ne!(fx.v1_tag_oid, fx.c2);
        for rev in ["v1.0.0", "refs/tags/v1.0.0"] {
            let src = GitSource::new(repo_str, rev, "");
            let res = client
                .resolve_revision(&src, &creds)
                .await
                .expect("resolve annotated tag");
            assert_eq!(res.commit_sha, fx.c2);
            assert_ne!(res.commit_sha, fx.v1_tag_oid);

            let co = client
                .checkout(&src, &res.commit_sha, &creds)
                .await
                .expect("checkout annotated tag");
            let tree = snapshot_tree(co.root_dir());
            assert_eq!(
                tree.get("README.md").map(String::as_str),
                Some("version=c2\n")
            );
            assert!(tree.contains_key("apps/overlays/prod/kustomization.yaml"));
            assert!(!tree.contains_key("CHANGELOG.md"));
        }

        // 5. Nested annotated tag -> peels all the way to c2!
        assert_ne!(fx.nested_tag_oid, fx.v1_tag_oid);
        assert_ne!(fx.nested_tag_oid, fx.c2);
        let nested_src = GitSource::new(repo_str, "v1.0.0-nested", "");
        let res_nested = client
            .resolve_revision(&nested_src, &creds)
            .await
            .expect("resolve nested tag");
        assert_eq!(res_nested.commit_sha, fx.c2);

        let co_nested = client
            .checkout(&nested_src, &res_nested.commit_sha, &creds)
            .await
            .expect("checkout nested tag");
        let tree_nested = snapshot_tree(co_nested.root_dir());
        assert_eq!(
            tree_nested.get("README.md").map(String::as_str),
            Some("version=c2\n")
        );

        // 5b. Lightweight tag pointing to annotated tag -> peels to c2
        let light_ann_src = GitSource::new(repo_str, &fx.light_to_annotated_tag, "");
        let res_light_ann = client
            .resolve_revision(&light_ann_src, &creds)
            .await
            .expect("resolve lightweight tag to annotated tag");
        assert_eq!(res_light_ann.commit_sha, fx.c2);
    }

    #[tokio::test]
    async fn resolve_and_checkout_historical_commit_sha_via_fallback_and_fast_path() {
        let fx = build_fixture();
        let client = local_client(None);
        let repo_str = fx.bare_path.to_str().expect("utf8 path");
        let creds = RepoCredentials::Anonymous;

        // 6a. Historical SHA c1 (NOT a branch tip, and allowReachableSHA1InWant is NOT set):
        // triggers shallow SHA-in-want failure -> fallback full fetch -> c1 found & checked out!
        let src_c1 = GitSource::new(repo_str, &fx.c1, "");
        let res_c1 = client
            .resolve_revision(&src_c1, &creds)
            .await
            .expect("resolve historical c1");
        assert_eq!(res_c1.commit_sha, fx.c1);

        let co_c1 = client
            .checkout(&src_c1, &fx.c1, &creds)
            .await
            .expect("checkout historical c1");
        let tree_c1 = snapshot_tree(co_c1.root_dir());
        assert_eq!(
            tree_c1.get("README.md").map(String::as_str),
            Some("version=c1\n")
        );
        assert!(!tree_c1.contains_key("apps/overlays/prod/kustomization.yaml"));
        assert!(!tree_c1.contains_key("CHANGELOG.md"));

        // 6b. Branch tip SHA c3 via fast path
        let src_c3 = GitSource::new(repo_str, &fx.c3, "");
        let res_c3 = client
            .resolve_revision(&src_c3, &creds)
            .await
            .expect("resolve tip sha c3");
        assert_eq!(res_c3.commit_sha, fx.c3);

        // 6c. Also test when uploadpack.allowReachableSHA1InWant=true (shallow SHA-in-want succeeds directly)
        git_cmd(
            &fx.bare_path,
            &["config", "uploadpack.allowReachableSHA1InWant", "true"],
        );
        let co_c1_direct = client
            .checkout(&src_c1, &fx.c1, &creds)
            .await
            .expect("checkout historical c1 with allowReachableSHA1InWant");
        let tree_c1_direct = snapshot_tree(co_c1_direct.root_dir());
        assert_eq!(
            tree_c1_direct.get("README.md").map(String::as_str),
            Some("version=c1\n")
        );
        assert!(!tree_c1_direct.contains_key("CHANGELOG.md"));
    }

    #[tokio::test]
    async fn nonexistent_revisions_return_revision_not_found() {
        let fx = build_fixture();
        let client = local_client(None);
        let repo_str = fx.bare_path.to_str().expect("utf8 path");
        let creds = RepoCredentials::Anonymous;

        let missing_sha = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        for rev in [
            "does-not-exist",
            "refs/heads/missing",
            "refs/tags/v99",
            missing_sha,
        ] {
            let src = GitSource::new(repo_str, rev, "");
            let err = client
                .resolve_revision(&src, &creds)
                .await
                .expect_err("missing revision should fail");
            assert!(
                matches!(err, RepoError::RevisionNotFound { .. }),
                "expected RevisionNotFound for {rev}, got {err:?}"
            );
            assert!(!err.is_retryable());
        }

        let err = client
            .checkout(&GitSource::new(repo_str, "main", ""), missing_sha, &creds)
            .await
            .expect_err("checkout missing sha should fail");
        assert!(matches!(err, RepoError::RevisionNotFound { .. }));
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn non_commit_oids_and_blob_tags_are_rejected_cleanly() {
        let fx = build_fixture();
        let client = local_client(None);
        let repo_str = fx.bare_path.to_str().expect("utf8 path");
        let creds = RepoCredentials::Anonymous;

        // 8a. Passing tag OID, blob OID, or tree OID to checkout must fail cleanly (never check out).
        for (label, oid) in [
            ("annotated tag OID", &fx.v1_tag_oid),
            ("nested tag OID", &fx.nested_tag_oid),
            ("blob OID", &fx.blob_oid),
            ("tree OID", &fx.tree_oid),
        ] {
            let src = GitSource::new(repo_str, "v1.0.0-nested", "");
            let err = client
                .checkout(&src, oid, &creds)
                .await
                .expect_err("non-commit OID must be rejected in checkout");
            assert!(
                matches!(err, RepoError::InvalidRevision { .. }),
                "expected InvalidRevision for {label} ({oid}), got {err:?}"
            );
            assert!(!err.is_retryable());

            let sha_src = GitSource::new(repo_str, oid, "");
            let resolve_err = client
                .resolve_revision(&sha_src, &creds)
                .await
                .expect_err("non-commit OID must be rejected in resolve_revision");
            assert!(
                matches!(resolve_err, RepoError::InvalidRevision { .. }),
                "expected InvalidRevision resolving {label} ({oid}), got {resolve_err:?}"
            );
            assert!(!resolve_err.is_retryable());
        }

        // 8b. Tags pointing to a blob or tree must be rejected by resolve_revision.
        for non_commit_tag in [&fx.blob_tag_name, &fx.tree_tag_name] {
            let non_commit_src = GitSource::new(repo_str, non_commit_tag, "");
            let err = client
                .resolve_revision(&non_commit_src, &creds)
                .await
                .expect_err("non-commit tag must not resolve as commit");
            assert!(
                matches!(err, RepoError::InvalidRevision { .. }),
                "expected InvalidRevision for {non_commit_tag}, got {err:?}"
            );
            assert!(!err.is_retryable());
        }
    }

    #[tokio::test]
    async fn empty_repo_and_detached_non_bare_worktree_behave_cleanly() {
        let empty_dir = tempfile::tempdir().expect("create empty repo dir");
        git_cmd(
            empty_dir.path(),
            &["init", "--bare", "--initial-branch=main"],
        );
        let client = local_client(None);
        let creds = RepoCredentials::Anonymous;
        let empty_url = empty_dir.path().to_str().expect("utf8");

        for rev in ["HEAD", "main", "0123456789abcdef0123456789abcdef01234567"] {
            let err = client
                .resolve_revision(&GitSource::new(empty_url, rev, ""), &creds)
                .await
                .expect_err("empty repo must return RevisionNotFound");
            assert!(
                matches!(err, RepoError::RevisionNotFound { .. }),
                "expected RevisionNotFound for {rev} on empty repo, got {err:?}"
            );
        }
        let co_err = client
            .checkout(
                &GitSource::new(empty_url, "HEAD", ""),
                "0123456789abcdef0123456789abcdef01234567",
                &creds,
            )
            .await
            .expect_err("checkout on empty repo must return RevisionNotFound");
        assert!(matches!(co_err, RepoError::RevisionNotFound { .. }));

        // Detached HEAD on non-bare local repository via file:// URL
        let fx = build_fixture();
        git_cmd(&fx.work_path, &["checkout", "--detach", &fx.c2]);
        let file_work_url = format!("file://{}", fx.work_path.to_str().expect("utf8"));
        let detached_src = GitSource::new(file_work_url, "HEAD", "");
        let res = client
            .resolve_revision(&detached_src, &creds)
            .await
            .expect("resolve detached HEAD");
        assert_eq!(res.commit_sha, fx.c2);

        let co = client
            .checkout(&detached_src, &res.commit_sha, &creds)
            .await
            .expect("checkout detached HEAD");
        assert_eq!(
            std::fs::read_to_string(co.root_dir().join("README.md")).expect("read README"),
            "version=c2\n"
        );
    }

    #[tokio::test]
    async fn production_policy_rejects_local_urls_while_allow_local_accepts_file_variants() {
        let fx = build_fixture();
        let prod_client = GixGitClient::default();
        let creds = RepoCredentials::Anonymous;

        let raw_path = fx.bare_path.to_str().expect("utf8 path");
        let file_triple_slash = format!("file://{raw_path}");
        let file_upper = format!("FILE://{raw_path}");
        let file_localhost = format!("file://localhost{raw_path}");

        for url in [
            raw_path,
            file_triple_slash.as_str(),
            file_upper.as_str(),
            file_localhost.as_str(),
        ] {
            let src = GitSource::new(url, "main", "");
            let err = prod_client
                .resolve_revision(&src, &creds)
                .await
                .expect_err("production policy must reject local URLs");
            assert!(matches!(err, RepoError::InvalidUrl { .. }));

            let co_err = prod_client
                .checkout(&src, &fx.c3, &creds)
                .await
                .expect_err("production policy must reject local URLs in checkout");
            assert!(matches!(co_err, RepoError::InvalidUrl { .. }));
        }

        let local = local_client(None);
        for url in [
            raw_path,
            file_triple_slash.as_str(),
            file_upper.as_str(),
            file_localhost.as_str(),
        ] {
            let src = GitSource::new(url, "main", "");
            let res = local
                .resolve_revision(&src, &creds)
                .await
                .expect("AllowLocal should resolve file/path URL");
            assert_eq!(res.commit_sha, fx.c3);

            let co = local
                .checkout(&src, &fx.c3, &creds)
                .await
                .expect("AllowLocal should checkout file/path URL");
            assert!(!co.root_dir().join(".git").exists());
            assert_eq!(
                std::fs::read_to_string(co.root_dir().join("README.md")).expect("read README"),
                "version=c3\n"
            );
        }
    }

    #[tokio::test]
    async fn checkout_raii_lease_cleans_up_temp_dir_and_respects_work_root() {
        let fx = build_fixture();
        let custom_work_root = tempfile::tempdir().expect("create custom work_root");
        let client = local_client(Some(custom_work_root.path().to_path_buf()));
        let src = GitSource::new(fx.bare_path.to_str().expect("utf8"), "main", "");
        let creds = RepoCredentials::Anonymous;

        let co = client
            .checkout(&src, &fx.c3, &creds)
            .await
            .expect("checkout under custom work_root");
        let worktree_path = co.root_dir().to_path_buf();
        assert!(worktree_path.starts_with(custom_work_root.path()));
        assert!(worktree_path.exists());
        assert!(!worktree_path.join(".git").exists());

        drop(co);
        assert!(
            !worktree_path.exists(),
            "dropping RepoCheckout must delete checked-out directory"
        );
        // Temporary bare repo should also have been cleaned up, leaving work_root empty.
        assert_eq!(
            std::fs::read_dir(custom_work_root.path())
                .expect("read work_root")
                .count(),
            0
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn checkout_sanitizes_symlinks_and_cleans_up_on_rejection() {
        let root = tempfile::tempdir().expect("create fixture root");
        let work = root.path().join("work");
        let bare = root.path().join("remote.git");
        std::fs::create_dir_all(&work).expect("mkdir work");

        git_cmd(&work, &["init", "--initial-branch=main"]);
        std::fs::write(work.join("README.md"), "hello\n").expect("write README");
        // (a) a valid intra-repo relative symlink.
        std::os::unix::fs::symlink("README.md", work.join("valid-link")).expect("valid symlink");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "valid symlink commit"]);
        let valid_sha = git_cmd(&work, &["rev-parse", "HEAD"]);

        // (b) a symlink escaping to /etc/passwd in a later commit.
        std::os::unix::fs::symlink("/etc/passwd", work.join("evil-link")).expect("evil symlink");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "evil symlink commit"]);
        let evil_sha = git_cmd(&work, &["rev-parse", "HEAD"]);

        // (c) a chained relative escape (`../../../`), proving verification (c) at the git layer
        // too: the link resolves to an *existing* file just outside the checkout root, so it is
        // the containment check (not a dangling target) that rejects it. The evil link is
        // removed first so every commit carries exactly one malicious symlink and the expected
        // path is deterministic regardless of directory-walk order.
        std::fs::remove_file(work.join("evil-link")).expect("remove evil symlink");
        std::fs::create_dir_all(work.join("sub")).expect("mkdir sub");
        std::os::unix::fs::symlink("../../../outside/secret.txt", work.join("sub/esc-link"))
            .expect("chained escape symlink");
        git_cmd(&work, &["add", "-A"]);
        git_cmd(&work, &["commit", "-m", "chained escape symlink commit"]);
        let chain_sha = git_cmd(&work, &["rev-parse", "HEAD"]);

        git_cmd(
            root.path(),
            &[
                "clone",
                "--bare",
                work.to_str().expect("utf8 path"),
                bare.to_str().expect("utf8 path"),
            ],
        );

        // The checkout root is `<client_work_root>/ferriscd-git-XXXX`, so `../../../` from
        // `<checkout>/sub` lands exactly on the scratch root, where `outside/secret.txt` lives.
        let scratch = tempfile::tempdir().expect("create client scratch root");
        let client_work_root = scratch.path().join("client-work");
        std::fs::create_dir_all(&client_work_root).expect("mkdir client work_root");
        std::fs::create_dir_all(scratch.path().join("outside")).expect("mkdir outside");
        std::fs::write(scratch.path().join("outside/secret.txt"), "secret\n")
            .expect("write outside secret");

        let client = local_client(Some(client_work_root.clone()));
        let repo_str = bare.to_str().expect("utf8 path");
        let creds = RepoCredentials::Anonymous;

        // The valid commit must checkout and the symlink must resolve within the worktree.
        let valid = client
            .checkout(&GitSource::new(repo_str, "main", ""), &valid_sha, &creds)
            .await
            .expect("valid intra-repo symlink checkout must succeed");
        assert_eq!(
            std::fs::read_to_string(valid.root_dir().join("valid-link")).expect("read link"),
            "hello\n"
        );

        // The malicious commits must fail cleanly with a terminal, non-retryable error.
        let err = client
            .checkout(&GitSource::new(repo_str, "main", ""), &evil_sha, &creds)
            .await
            .expect_err("symlink to /etc/passwd must be rejected");
        assert!(
            matches!(err, RepoError::UnsafeSymlink { .. }),
            "expected UnsafeSymlink, got {err:?}"
        );
        assert!(!err.is_retryable());
        match &err {
            RepoError::UnsafeSymlink { reason, .. } => {
                assert!(reason.contains("escapes"), "unexpected reason: {reason}");
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }

        let chain_err = client
            .checkout(&GitSource::new(repo_str, "main", ""), &chain_sha, &creds)
            .await
            .expect_err("chained relative symlink escape must be rejected");
        assert!(!chain_err.is_retryable(), "escape must be terminal");
        match &chain_err {
            RepoError::UnsafeSymlink {
                path,
                target,
                reason,
            } => {
                assert!(path.ends_with("sub/esc-link"), "unexpected path: {path:?}");
                assert_eq!(target, &PathBuf::from("../../../outside/secret.txt"));
                assert!(reason.contains("escapes"), "unexpected reason: {reason}");
            }
            other => panic!("expected UnsafeSymlink, got {other:?}"),
        }

        // Drop the successful checkout to release its temp dir, then assert the failing
        // checkouts left no materialized worktree (or bare repo) behind.
        drop(valid);
        assert_eq!(
            std::fs::read_dir(&client_work_root)
                .expect("read client work_root")
                .count(),
            0,
            "temp checkout and bare repo must be cleaned up after a rejected checkout"
        );
    }

    /// The configurable byte budget is enforced by [`GixGitClient`] itself, against a real
    /// commit, and a rejected worktree is not left behind.
    #[tokio::test]
    async fn checkout_enforces_configured_byte_budget_on_a_real_commit() {
        let fx = build_fixture();
        let client_work_root = tempfile::tempdir().expect("create client work_root");
        let client = GixGitClient::new(
            GixGitClientConfig::new()
                .with_url_policy(RepoUrlPolicy::AllowLocal)
                .with_work_root(client_work_root.path().to_path_buf())
                .with_worktree_limits(WorktreeLimits::new().with_max_bytes(8)),
        );
        let src = GitSource::new(fx.bare_path.to_str().expect("utf8 path"), "main", "");

        let err = client
            .checkout(&src, &fx.c1, &RepoCredentials::Anonymous)
            .await
            .expect_err("the commit's regular-file content exceeds the 8-byte budget");
        assert!(
            matches!(err, RepoError::CheckoutLimitExceeded { .. }),
            "expected CheckoutLimitExceeded, got {err:?}"
        );
        assert!(!err.is_retryable(), "a budget violation must be terminal");
        assert_eq!(
            std::fs::read_dir(client_work_root.path())
                .expect("read client work_root")
                .count(),
            0,
            "a rejected checkout must not leave its worktree or bare repo behind"
        );
    }

    #[tokio::test]
    async fn credentials_incompatible_with_file_urls_fail_without_leaking_secrets() {
        // A local (`file://`) fixture can never be authenticated: HTTPS credentials and SSH keys
        // are rejected as terminal misconfiguration before any transport is spawned.
        let fx = build_fixture();
        let client = local_client(None);
        let src = GitSource::new(fx.bare_path.to_str().expect("utf8"), "main", "");

        let secrets = [
            "secret-token-value",
            "secret-user",
            "secret-pass",
            "PRIVATE_KEY_BODY",
        ];
        let creds_list = [
            RepoCredentials::HttpToken {
                token: "secret-token-value".to_owned(),
            },
            RepoCredentials::HttpBasic {
                username: "secret-user".to_owned(),
                password: "secret-pass".to_owned(),
            },
            RepoCredentials::SshKey {
                private_key_pem: "PRIVATE_KEY_BODY".to_owned(),
                passphrase: Some("secret-pass".to_owned()),
                known_hosts: None,
            },
        ];

        for creds in &creds_list {
            let err1 = client
                .resolve_revision(&src, creds)
                .await
                .expect_err("incompatible creds must return AuthFailed");
            assert!(matches!(err1, RepoError::AuthFailed { .. }));
            assert!(!err1.is_retryable());

            let err2 = client
                .checkout(&src, &fx.c3, creds)
                .await
                .expect_err("incompatible creds must return AuthFailed");
            assert!(matches!(err2, RepoError::AuthFailed { .. }));
            assert!(!err2.is_retryable());

            for err in [&err1, &err2] {
                let text = format!("{err} {err:?}");
                for secret in secrets {
                    assert!(!text.contains(secret), "secret leaked in error: {text}");
                }
            }
        }
    }

    #[test]
    fn parse_gix_url_rejects_remote_file_hosts_and_normalizes_localhost() {
        let local_policy = RepoUrlPolicy::AllowLocal;
        for url in [
            "file://localhost/tmp/repo",
            "file://LOCALHOST/tmp/repo",
            "FILE://LocalHost/tmp/repo",
        ] {
            let ok = parse_gix_url(url, local_policy).expect("localhost allowed");
            assert_eq!(ok.scheme, gix::url::Scheme::File);
            assert_eq!(ok.host(), None);
            assert_eq!(ok.path, "/tmp/repo");
        }

        let upper =
            parse_gix_url("FILE:///tmp/repo", local_policy).expect("uppercase FILE allowed");
        assert_eq!(upper.scheme, gix::url::Scheme::File);
        assert_eq!(upper.path, "/tmp/repo");

        let https_upper =
            parse_gix_url("HTTPS://github.com/org/repo.git", RepoUrlPolicy::Production)
                .expect("uppercase HTTPS allowed");
        assert_eq!(https_upper.scheme, gix::url::Scheme::Https);

        let remote_host = parse_gix_url("file://evil.example/tmp/repo", local_policy)
            .expect_err("non-localhost file host must be rejected");
        assert!(matches!(remote_host, RepoError::InvalidUrl { .. }));
    }

    #[tokio::test]
    async fn ssh_urls_with_anonymous_credentials_fail_without_spawning_ssh() {
        // Anonymous SSH can never be host-key verified, so it is rejected before any `ssh`
        // process is spawned (and before any known_hosts/key material exists).
        let creds = RepoCredentials::Anonymous;
        let sha = "0123456789abcdef0123456789abcdef01234567";

        for client in [GixGitClient::default(), local_client(None)] {
            for url in [
                "ssh://git@github.com/org/repo.git",
                "SSH://git@github.com:2222/org/repo.git",
                "git@github.com:org/repo.git",
            ] {
                let src = GitSource::new(url, "main", "");
                let res_err = client
                    .resolve_revision(&src, &creds)
                    .await
                    .expect_err("anonymous SSH must fail cleanly");
                assert!(
                    matches!(res_err, RepoError::HostKeyVerificationFailed { .. }),
                    "expected HostKeyVerificationFailed resolving {url}, got {res_err:?}"
                );
                assert!(!res_err.is_retryable());

                let co_err = client
                    .checkout(&src, sha, &creds)
                    .await
                    .expect_err("anonymous SSH checkout must fail cleanly");
                assert!(
                    matches!(co_err, RepoError::HostKeyVerificationFailed { .. }),
                    "expected HostKeyVerificationFailed checking out {url}, got {co_err:?}"
                );
                assert!(!co_err.is_retryable());
            }
        }
    }

    #[tokio::test]
    async fn ssh_key_without_known_hosts_is_rejected_before_spawning_ssh() {
        let creds = RepoCredentials::SshKey {
            private_key_pem:
                "-----BEGIN OPENSSH PRIVATE KEY-----\nBODY\n-----END OPENSSH PRIVATE KEY-----"
                    .to_owned(),
            passphrase: None,
            known_hosts: None,
        };
        let client = GixGitClient::default();
        let src = GitSource::new("ssh://git@example.invalid/org/repo.git", "main", "");
        let err = client
            .resolve_revision(&src, &creds)
            .await
            .expect_err("missing known_hosts must be rejected");
        match &err {
            RepoError::HostKeyVerificationFailed { host, reason } => {
                assert_eq!(host, "example.invalid");
                assert!(reason.contains("known_hosts"), "{reason}");
            }
            other => panic!("expected HostKeyVerificationFailed, got {other:?}"),
        }
        assert!(!err.is_retryable());
        assert!(!format!("{err} {err:?}").contains("BODY"));
    }

    /// Records every invocation of a fake `ssh` program into a log file, then fails.
    ///
    /// Keeping the recorder out-of-process lets the test prove the *real* spawn saw the
    /// ephemeral `0600` key (mode and existence are checked by the script itself while it runs).
    #[cfg(unix)]
    fn write_fake_ssh(dir: &Path, log: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        // A deliberately hostile program path: the command must be shell-quoted correctly
        // (`'...fake ssh dir/fake'\''ssh'`) for the script to even run.
        let script_dir = dir.join("fake ssh dir");
        std::fs::create_dir_all(&script_dir).expect("create fake ssh dir");
        let script = script_dir.join("fake'ssh");
        let body = format!(
            r#"#!/bin/sh
log='{log}'
printf 'CALL\n' >> "$log"
prev=''
key=''
for arg in "$@"; do
  printf 'ARG:%s\n' "$arg" >> "$log"
  if [ "$prev" = "-i" ]; then key="$arg"; fi
  prev="$arg"
done
if [ -n "$key" ]; then
  if [ -f "$key" ]; then
    printf 'KEY_EXISTS\n' >> "$log"
  else
    printf 'KEY_MISSING\n' >> "$log"
  fi
  mode=$(stat -c '%a' "$key" 2>/dev/null || stat -f '%Lp' "$key" 2>/dev/null)
  printf 'KEY_MODE:%s\n' "$mode" >> "$log"
  printf 'KEY_DIR:%s\n' "$(dirname "$key")" >> "$log"
fi
exit 255
"#,
            log = log.display()
        );
        std::fs::write(&script, body).expect("write fake ssh script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat script")
            .permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&script, perms).expect("chmod fake ssh script");
        script
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_transport_passes_hardened_command_and_cleans_up_ephemeral_key() {
        // Local bare-repo fixture (same git-CLI pattern as the rest of this module); the fake
        // `ssh` never connects, so the remote URL only has to look like a real SSH remote.
        let fx = build_fixture();
        let scratch = tempfile::tempdir().expect("create ssh scratch root");
        let log = scratch.path().join("ssh-args.log");
        let fake_ssh = write_fake_ssh(scratch.path(), &log);
        assert!(
            fake_ssh.to_str().expect("utf8 fake ssh path").contains(' '),
            "the fixture must exercise shell quoting of the ssh program path"
        );

        let creds = RepoCredentials::SshKey {
            private_key_pem: "-----BEGIN OPENSSH PRIVATE KEY-----\nSUPER_SECRET_KEY_BODY\n-----END OPENSSH PRIVATE KEY-----"
                .to_owned(),
            passphrase: None,
            known_hosts: Some(
                "example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISECRETHOSTKEY".to_owned(),
            ),
        };
        let client = GixGitClient::new(
            GixGitClientConfig::new()
                .with_url_policy(RepoUrlPolicy::Production)
                .with_ssh_program(fake_ssh)
                .with_work_root(scratch.path().join("work")),
        );
        let url = format!(
            "ssh://git@example.invalid{}",
            fx.bare_path.to_str().expect("utf8 path")
        );
        let src = GitSource::new(&url, "main", "");

        let err = client
            .resolve_revision(&src, &creds)
            .await
            .expect_err("fake ssh always fails");

        // The failure is clean and secret-free, never a panic/abort.
        let text = format!("{err} {err:?}");
        assert!(!text.contains("SUPER_SECRET_KEY_BODY"), "{text}");
        assert!(!text.contains("SECRETHOSTKEY"), "{text}");

        let recorded = std::fs::read_to_string(&log).expect("fake ssh must have been invoked");
        assert!(recorded.contains("CALL"), "{recorded}");

        // The temp key directory must be recorded while ssh is running...
        let key_dir = recorded
            .lines()
            .find_map(|line| line.strip_prefix("KEY_DIR:"))
            .expect("fake ssh must record the key directory")
            .to_owned();
        assert!(
            key_dir.contains("ferriscd-ssh-"),
            "ephemeral key must live in a dedicated scratch dir: {key_dir}"
        );
        assert!(
            recorded.contains(&format!("ARG:{key_dir}/ferriscd-deploy-key")),
            "`-i` must point at the ephemeral key inside {key_dir}:\n{recorded}"
        );
        // The exact scratch `known_hosts` path must reach ssh, not just the option prefix.
        let expected_known_hosts = format!("ARG:UserKnownHostsFile={key_dir}/known_hosts");
        assert!(
            recorded.lines().any(|line| line == expected_known_hosts),
            "ssh must receive exactly {expected_known_hosts}:\n{recorded}"
        );
        for expected in [
            "-i",
            "IdentitiesOnly=yes",
            "StrictHostKeyChecking=yes",
            "UserKnownHostsFile=",
            "BatchMode=yes",
            "git@example.invalid",
            "KEY_EXISTS",
        ] {
            assert!(
                recorded.contains(expected),
                "recorded ssh invocation missing {expected}:\n{recorded}"
            );
        }
        assert!(
            !recorded.contains("KEY_MISSING"),
            "the ephemeral key must exist while ssh runs:\n{recorded}"
        );
        assert!(
            recorded.contains("KEY_MODE:600"),
            "the ephemeral key must be 0600 while ssh runs:\n{recorded}"
        );

        // ...and must be gone once the blocking operation finished.
        assert!(
            !Path::new(&key_dir).exists(),
            "ephemeral SSH key directory must be removed: {key_dir}"
        );
    }

    #[test]
    fn isolated_bare_repo_disables_http_redirects_and_restricts_protocols() {
        let prod_dir = tempfile::tempdir().expect("prod bare dir");
        let auth = anonymous_auth();
        let prod_repo = init_isolated_bare_repo(
            prod_dir.path(),
            &blocking_ctx(&auth, RepoUrlPolicy::Production),
        )
        .expect("init prod bare repo");
        let prod_cfg = prod_repo.config_snapshot();
        assert_eq!(prod_cfg.boolean("http.followRedirects"), Some(false));
        assert_eq!(
            prod_cfg.string("protocol.allow"),
            Some(gix::bstr::BString::from("never"))
        );
        assert_eq!(
            prod_cfg.string("protocol.https.allow"),
            Some(gix::bstr::BString::from("always"))
        );
        // SSH is a production transport (key + strict host key verification).
        assert_eq!(
            prod_cfg.string("protocol.ssh.allow"),
            Some(gix::bstr::BString::from("always"))
        );
        assert!(prod_cfg.string("protocol.http.allow").is_none());
        assert!(prod_cfg.string("protocol.file.allow").is_none());
        assert!(
            prod_cfg.string("protocol.git.allow").is_none(),
            "the unauthenticated git:// protocol must stay disabled"
        );
        assert!(prod_cfg.string("core.sshCommand").is_none());

        let local_dir = tempfile::tempdir().expect("local bare dir");
        let local_repo = init_isolated_bare_repo(
            local_dir.path(),
            &blocking_ctx(&auth, RepoUrlPolicy::AllowLocal),
        )
        .expect("init local bare repo");
        let local_cfg = local_repo.config_snapshot();
        assert_eq!(local_cfg.boolean("http.followRedirects"), Some(false));
        assert_eq!(
            local_cfg.string("protocol.file.allow"),
            Some(gix::bstr::BString::from("always"))
        );
        assert_eq!(
            local_cfg.string("protocol.ssh.allow"),
            Some(gix::bstr::BString::from("always"))
        );
        assert!(local_cfg.string("protocol.git.allow").is_none());
    }

    #[test]
    fn isolated_bare_repo_applies_ssh_command_override_for_key_credentials() {
        let url = gix::url::parse(b"ssh://git@example.invalid/org/repo.git".as_slice())
            .expect("valid ssh url");
        let creds = RepoCredentials::SshKey {
            private_key_pem: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_BODY\n-----END OPENSSH PRIVATE KEY-----"
                .to_owned(),
            passphrase: None,
            known_hosts: Some("example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKEY".to_owned()),
        };
        let auth = AuthContext::new(&creds, &url, false, None).expect("auth context");
        let dir = tempfile::tempdir().expect("bare dir");
        let repo =
            init_isolated_bare_repo(dir.path(), &blocking_ctx(&auth, RepoUrlPolicy::Production))
                .expect("init bare repo");

        let ssh_command = repo
            .config_snapshot()
            .string("core.sshCommand")
            .map(|value| value.to_string())
            .expect("core.sshCommand must be overridden");
        assert!(ssh_command.contains("-i "), "{ssh_command}");
        assert!(
            ssh_command.contains("StrictHostKeyChecking=yes"),
            "{ssh_command}"
        );
        assert!(ssh_command.contains("UserKnownHostsFile="), "{ssh_command}");
        assert!(ssh_command.contains("IdentitiesOnly=yes"), "{ssh_command}");
        assert!(ssh_command.contains("BatchMode=yes"), "{ssh_command}");
        assert!(
            !ssh_command.contains("SECRET_BODY"),
            "private key material must never reach configuration"
        );

        // `gix` resolves this override exactly like `GIT_SSH_COMMAND` when building an SSH remote.
        let ssh_options = repo.ssh_connect_options().expect("ssh connect options");
        assert_eq!(
            ssh_options.ssh_command().to_str(),
            Some(ssh_command.as_str()),
            "gix must use the overridden ssh command for SSH remotes"
        );
        // `ssh.variant=ssh` keeps the command OpenSSH-shaped, so ports are supported.
        assert!(
            matches!(
                ssh_options.kind,
                Some(gix::protocol::transport::client::blocking_io::ssh::ProgramKind::Ssh)
            ),
            "the ssh variant must be pinned to OpenSSH, got {:?}",
            ssh_options.kind
        );

        // The key file must not leak into the on-disk `.git/config`.
        let config_on_disk =
            std::fs::read_to_string(dir.path().join("config")).expect("read config");
        assert!(!config_on_disk.contains("UserKnownHostsFile"));
        assert!(!config_on_disk.contains("SECRET_BODY"));
    }

    #[test]
    fn allow_missing_known_hosts_defaults_to_false_and_round_trips() {
        assert!(
            !GixGitClientConfig::default().allow_missing_known_hosts,
            "strict host key verification must be the default"
        );
        assert!(!GixGitClientConfig::new().allow_missing_known_hosts);

        let insecure = GixGitClientConfig::new().with_allow_missing_known_hosts(true);
        assert!(insecure.allow_missing_known_hosts);
        assert_eq!(
            insecure,
            GixGitClientConfig::new().with_allow_missing_known_hosts(true),
            "the builder must round-trip the flag"
        );
        // The flag must survive into the blocking layer that builds the `AuthContext`.
        assert!(insecure.blocking_options().allow_missing_known_hosts);
        assert!(
            GixGitClient::new(insecure.clone())
                .config()
                .allow_missing_known_hosts
        );

        let url = gix::url::parse(b"ssh://git@example.invalid/org/repo.git".as_slice())
            .expect("valid ssh url");
        let creds = RepoCredentials::SshKey {
            private_key_pem: "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET_BODY\n-----END OPENSSH PRIVATE KEY-----"
                .to_owned(),
            passphrase: None,
            known_hosts: None,
        };

        let auth = insecure
            .blocking_options()
            .auth_context(&url, &creds)
            .expect("the insecure dev flag must allow a missing known_hosts");
        let command = auth.ssh_command().expect("ssh command").to_owned();
        assert!(
            command.contains("StrictHostKeyChecking=accept-new"),
            "the insecure dev flag must use trust-on-first-use: {command}"
        );
        assert!(!command.contains("StrictHostKeyChecking=yes"), "{command}");
        assert!(command.contains("UserKnownHostsFile="), "{command}");
        assert!(command.contains("BatchMode=yes"), "{command}");
        assert!(!command.contains("SECRET_BODY"), "{command}");

        // The default configuration still rejects the very same credentials.
        let err = GixGitClientConfig::new()
            .blocking_options()
            .auth_context(&url, &creds)
            .expect_err("the default config must reject a missing known_hosts");
        assert!(matches!(err, RepoError::HostKeyVerificationFailed { .. }));
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn checkout_falls_back_when_branch_moved_past_target_sha() {
        let fx = build_fixture();
        let client = local_client(None);
        let repo_str = fx.bare_path.to_str().expect("utf8");
        let creds = RepoCredentials::Anonymous;

        // target_revision is "main" (tip = c3), so depth=1 shallow fetch only gets c3;
        // fallback must fetch full history and materialize historical commit c1.
        let src = GitSource::new(repo_str, "main", "");
        let co = client
            .checkout(&src, &fx.c1, &creds)
            .await
            .expect("checkout older sha c1 via moved branch fallback");
        let tree = snapshot_tree(co.root_dir());
        assert_eq!(
            tree.get("README.md").map(String::as_str),
            Some("version=c1\n")
        );
        assert!(!tree.contains_key("CHANGELOG.md"));
        assert!(!tree.contains_key("apps/overlays/prod/kustomization.yaml"));
    }

    #[tokio::test]
    async fn checkout_preserves_executable_bit_and_handles_empty_commit_tree() {
        let root = tempfile::tempdir().expect("create temp dir");
        let work = root.path().join("work");
        let bare = root.path().join("remote.git");
        std::fs::create_dir_all(&work).expect("mkdir work");

        git_cmd(&work, &["init", "--initial-branch=main"]);
        std::fs::write(work.join("run.sh"), "#!/bin/sh\necho ok\n").expect("write script");
        git_cmd(&work, &["add", "run.sh"]);
        git_cmd(&work, &["update-index", "--chmod=+x", "run.sh"]);
        git_cmd(&work, &["commit", "-m", "executable script"]);
        let exec_sha = git_cmd(&work, &["rev-parse", "HEAD"]);

        git_cmd(&work, &["checkout", "--orphan", "empty-tree"]);
        git_cmd(&work, &["rm", "-rf", "."]);
        git_cmd(&work, &["commit", "--allow-empty", "-m", "empty tree"]);
        let empty_sha = git_cmd(&work, &["rev-parse", "HEAD"]);

        git_cmd(&work, &["checkout", "main"]);
        git_cmd(
            root.path(),
            &[
                "clone",
                "--bare",
                work.to_str().expect("utf8"),
                bare.to_str().expect("utf8"),
            ],
        );

        let client = local_client(None);
        let creds = RepoCredentials::Anonymous;
        let repo_str = bare.to_str().expect("utf8");

        let exec_co = client
            .checkout(&GitSource::new(repo_str, "main", ""), &exec_sha, &creds)
            .await
            .expect("checkout executable file");
        let script_path = exec_co.root_dir().join("run.sh");
        assert!(script_path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&script_path)
                .expect("stat script")
                .permissions()
                .mode();
            assert_ne!(
                mode & 0o111,
                0,
                "executable bit should be preserved: {mode:#o}"
            );
        }

        let empty_co = client
            .checkout(
                &GitSource::new(repo_str, "empty-tree", ""),
                &empty_sha,
                &creds,
            )
            .await
            .expect("checkout empty commit tree");
        assert!(!empty_co.root_dir().join(".git").exists());
        assert_eq!(
            std::fs::read_dir(empty_co.root_dir())
                .expect("read empty checkout")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn symbolic_head_pointing_to_tag_and_custom_ref_resolve_and_checkout() {
        let fx = build_fixture();
        let client = local_client(None);
        let creds = RepoCredentials::Anonymous;
        let repo_str = fx.bare_path.to_str().expect("utf8");

        // Custom ref (e.g. PR head) pointing to an orphan commit not reachable from branches/tags
        git_cmd(&fx.work_path, &["checkout", "--orphan", "pr-temp"]);
        git_cmd(&fx.work_path, &["rm", "-rf", "."]);
        std::fs::write(fx.work_path.join("PR.md"), "pr-42\n").expect("write PR.md");
        git_cmd(&fx.work_path, &["add", "PR.md"]);
        git_cmd(&fx.work_path, &["commit", "-m", "pr 42"]);
        let pr_sha = git_cmd(&fx.work_path, &["rev-parse", "HEAD"]);
        git_cmd(
            &fx.bare_path,
            &[
                "fetch",
                fx.work_path.to_str().expect("utf8"),
                &format!("{pr_sha}:refs/pull/42/head"),
            ],
        );

        let pr_src = GitSource::new(repo_str, "refs/pull/42/head", "");
        let pr_res = client
            .resolve_revision(&pr_src, &creds)
            .await
            .expect("resolve custom ref refs/pull/42/head");
        assert_eq!(pr_res.commit_sha, pr_sha);

        // Verify fallback refspecs include custom ref when checking out a different/older SHA or forced fallback
        let pr_co = client
            .checkout(&pr_src, &pr_sha, &creds)
            .await
            .expect("checkout custom ref");
        assert_eq!(
            std::fs::read_to_string(pr_co.root_dir().join("PR.md")).expect("read PR.md"),
            "pr-42\n"
        );
        assert!(
            build_fallback_refspecs("refs/pull/42/head")
                .iter()
                .any(|s| s == "+refs/pull/42/head:refs/remotes/origin/custom-target")
        );

        // Symbolic HEAD pointing directly to annotated tag refs/tags/v1.0.0 -> peels to c2
        git_cmd(&fx.bare_path, &["symbolic-ref", "HEAD", "refs/tags/v1.0.0"]);
        let head_src = GitSource::new(repo_str, "HEAD", "");
        let head_res = client
            .resolve_revision(&head_src, &creds)
            .await
            .expect("resolve HEAD symbolic to annotated tag");
        assert_eq!(head_res.commit_sha, fx.c2);

        let head_co = client
            .checkout(&head_src, &head_res.commit_sha, &creds)
            .await
            .expect("checkout HEAD symbolic to tag");
        assert_eq!(
            std::fs::read_to_string(head_co.root_dir().join("README.md")).expect("read README"),
            "version=c2\n"
        );
    }

    #[tokio::test]
    async fn null_oid_is_rejected_and_fatal_fallback_rules_hold() {
        let fx = build_fixture();
        let client = local_client(None);
        let creds = RepoCredentials::Anonymous;
        let repo_str = fx.bare_path.to_str().expect("utf8");
        let null_sha = "0000000000000000000000000000000000000000";

        let res_err = client
            .resolve_revision(&GitSource::new(repo_str, null_sha, ""), &creds)
            .await
            .expect_err("null oid must fail");
        assert!(matches!(res_err, RepoError::RevisionNotFound { .. }));

        let co_err = client
            .checkout(&GitSource::new(repo_str, "main", ""), null_sha, &creds)
            .await
            .expect_err("checkout null oid must fail");
        assert!(matches!(co_err, RepoError::RevisionNotFound { .. }));

        let null_oid_err =
            validate_resolved_oid(gix::ObjectId::null(gix::hash::Kind::Sha1), "HEAD")
                .expect_err("null object id helper must reject");
        assert!(matches!(null_oid_err, RepoError::RevisionNotFound { .. }));

        // Fatal vs fallback truth table
        assert!(is_fatal_without_fallback(&RepoError::AuthFailed {
            reason: "401".into()
        }));
        assert!(is_fatal_without_fallback(&RepoError::Network {
            message: "reset".into()
        }));
        assert!(is_fatal_without_fallback(&RepoError::Timeout {
            message: "timed out".into()
        }));
        assert!(is_fatal_without_fallback(&RepoError::RemoteServerError {
            status: Some(503),
            message: "unavailable".into()
        }));
        assert!(is_fatal_without_fallback(&RepoError::TaskCancelled {
            message: "cancelled".into()
        }));
        assert!(is_fatal_without_fallback(&RepoError::InvalidUrl {
            url: "https://example.com".into(),
            reason: "bad".into()
        }));
        assert!(!is_fatal_without_fallback(&RepoError::RevisionNotFound {
            revision: "main".into()
        }));
        assert!(!is_fatal_without_fallback(&RepoError::RepositoryError {
            message: "not our ref".into()
        }));
        assert!(!is_fatal_without_fallback(&RepoError::RemoteServerError {
            status: None,
            message: "transient".into()
        }));
    }

    #[test]
    fn map_gix_error_classifies_transport_auth_timeout_and_http_errors() {
        use gix::error::{Class, ClassificationMarker, ErrorExt, message};
        use gix::protocol::transport::{client, packetline};

        let cancelled = map_gix_error(gix::Error::from_error(gix::error::cancelled("aborted")));
        assert!(matches!(cancelled, RepoError::TaskCancelled { .. }));
        assert!(cancelled.is_retryable());

        let auth_req = map_gix_error(gix::Error::from_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            client::AuthenticationRequired::default(),
        )));
        assert!(matches!(auth_req, RepoError::AuthFailed { .. }));
        assert!(!auth_req.is_retryable());

        let http_403 = map_gix_error(
            ClassificationMarker::with_source(Class::PermissionDenied, message("forbidden"))
                .and_raise(message("Received HTTP status 403")),
        );
        assert!(matches!(http_403, RepoError::AuthFailed { .. }));
        assert!(!http_403.is_retryable());

        let http_503 = map_gix_error(gix::Error::from_error(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            ClassificationMarker::with_source(Class::Retryable, message("upstream"))
                .and_raise(message("Received HTTP status 503")),
        )));
        assert!(matches!(
            http_503,
            RepoError::RemoteServerError {
                status: Some(503),
                ..
            }
        ));
        assert!(http_503.is_retryable());

        let http_404 = map_gix_error(gix::Error::from_error(std::io::Error::other(message(
            "Received HTTP status 404",
        ))));
        assert!(matches!(
            http_404,
            RepoError::RemoteServerError {
                status: Some(404),
                ..
            }
        ));
        assert!(!http_404.is_retryable());

        let timeout = map_gix_error(gix::Error::from_error(std::io::Error::from(
            std::io::ErrorKind::TimedOut,
        )));
        assert!(matches!(timeout, RepoError::Timeout { .. }));
        assert!(timeout.is_retryable());

        let network = map_gix_error(gix::Error::from_error(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )));
        assert!(matches!(network, RepoError::Network { .. }));
        assert!(network.is_retryable());

        let pkt_auth = map_gix_error(gix::Error::from_error(packetline::read::Error {
            message: "Permission denied for repository".into(),
        }));
        assert!(matches!(pkt_auth, RepoError::AuthFailed { .. }));

        let pkt_ref = map_gix_error(gix::Error::from_error(packetline::read::Error {
            message: "not our ref deadbeef".into(),
        }));
        assert!(matches!(pkt_ref, RepoError::RepositoryError { .. }));
        assert!(!pkt_ref.is_retryable());

        for kind in [
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::IsADirectory,
        ] {
            let err = map_gix_error(gix::Error::from_error(std::io::Error::from(kind)));
            assert!(
                matches!(err, RepoError::RepositoryError { .. }),
                "expected RepositoryError for {kind:?}, got {err:?}"
            );
            assert!(!err.is_retryable());
        }
    }
}
