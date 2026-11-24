//! Deterministic, zero-network [`GitClient`] test harness.
//!
//! Every phase after 02 (rendering, diffing, sync planning, rollback, health) needs Git
//! fixtures that are fast, hermetic, and scriptable: commits, branch switches, historical
//! commits, and reproducible outages. [`FakeGitClient`] provides exactly that: an in-memory
//! object store whose checkouts materialize real files on disk, so downstream tests exercise
//! the *same* [`super::RepoCache`] and renderer code paths as production while never touching
//! the network or invoking `git`.
//!
//! # Availability
//!
//! The module is compiled for this crate's own tests and, for downstream crates
//! (`ferriscd-controller`, integration tests), whenever the `test-utils` Cargo feature is
//! enabled:
//!
//! ```text
//! # Cargo.toml of a downstream crate
//! [dev-dependencies]
//! ferriscd-engine = { path = "../ferriscd-engine", features = ["test-utils"] }
//! ```
//!
//! # Design
//!
//! * **Interior mutability.** [`FakeGitClient`] is `Clone + Send + Sync` and shares one
//!   `Arc<Mutex<…>>` state, so a fixture can be handed to concurrent Tokio tasks (or cloned
//!   into a test) while commits are still being added.
//! * **Immutable, addressable commits.** [`FakeGitClient::add_commit`] appends a new commit
//!   and advances a branch; nothing is ever mutated in place, so every historical commit
//!   stays resolvable and checkable.
//! * **Deterministic SHAs.** Commit SHAs are derived from `(parent, branch, ordinal, files)`
//!   with FNV-1a, so the same script of `add_commit` calls always yields the same 40-character
//!   lowercase hex SHA — valid per [`super::validate_commit_sha`] — on every platform and run.
//! * **Real checkouts, no `.git`.** [`GitClient::checkout`] writes the commit's files into a
//!   fresh [`tempfile::TempDir`] (under [`FakeGitClientConfig::work_root`], defaulting to the
//!   system temp directory) and returns it as the [`RepoCheckout`] lease, so the directory is
//!   removed on drop and no Git metadata is ever created. The temporary directory is created
//!   *inside* `work_root` (like [`super::GixGitClient`]) so a [`super::RepoCache`] pointed at
//!   the same root can publish it with an atomic `rename(2)`.
//! * **Fault injection.** Failures are queued per [`FakeStage`] and consumed in order, so a
//!   test can script "transient outage, then success" (retry loops) or a terminal failure
//!   (no retry) without any timing sleeps.
//! * **Uniform validation.** [`GitSource::validate`] runs at the start of every operation with
//!   [`FakeGitClientConfig::url_policy`], exactly like [`super::GixGitClient`], and *before* a
//!   queued fault is consumed — so a fake and the real client classify bad input identically.
//! * **Call recording.** Resolve/checkout counters and request logs let cache and client tests
//!   assert hit/miss behaviour and retry counts.
//!
//! The harness never panics: a poisoned state mutex is recovered from
//! ([`std::sync::PoisonError::into_inner`]) and surfaced as an ordinary result, and an invalid
//! (escaping) commit path is reported as a terminal [`RepoError::InvalidSource`] at checkout
//! time instead of being written outside the checkout root.
//!
//! Symlinks are deliberately *not* representable in a fake commit: crafted symlink trees are
//! the subject of [`super::sanitize`] and are built with real `git` in its tests (see
//! `docs/lessons/02-git-internals-and-repo-caching.md`). [`super::RepoCache`] still sanitizes
//! every tree a fake materializes, so symlink defenses stay covered on the cache path.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use super::error::RepoError;
use super::types::{
    GitSource, RepoCheckout, RepoCredentials, RepoUrlPolicy, ResolvedRevision, validate_commit_sha,
};
use super::{GitClient, RepoFuture};

/// FNV-1a 64-bit offset basis (primary hash seed).
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Secondary seed producing the second 64-bit half of a fake commit SHA.
const SECONDARY_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

/// Prefix of every temporary checkout directory, mirroring [`super::GixGitClient`].
const TEMP_PREFIX: &str = "ferriscd-fake-";

/// Stage of a repository operation that a [`FakeGitClient`] can be scripted to fail.
///
/// Faults are queued per stage, so an outage in `resolve` never leaks into a `checkout` and
/// vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FakeStage {
    /// [`GitClient::resolve_revision`] (ref lookup, i.e. the fetch/ls-remote stage).
    Resolve,
    /// [`GitClient::checkout`] (materialization stage).
    Checkout,
}

/// `HEAD` state of a [`FakeGitClient`] repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeHead {
    /// `HEAD` is a symbolic ref pointing at this branch.
    Branch(String),
    /// `HEAD` is detached at this commit SHA.
    Detached(String),
}

/// Configuration for [`FakeGitClient`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeGitClientConfig {
    /// Policy enforced on [`GitSource`] URLs at the start of every operation.
    ///
    /// Defaults to [`RepoUrlPolicy::Production`], matching [`super::GixGitClient`]: tests must
    /// opt in explicitly to `file://` / local-path sources.
    pub url_policy: RepoUrlPolicy,
    /// Parent directory for materialized checkouts. `None` uses the system temp directory.
    pub work_root: Option<PathBuf>,
}

impl Default for FakeGitClientConfig {
    fn default() -> Self {
        Self {
            url_policy: RepoUrlPolicy::Production,
            work_root: None,
        }
    }
}

impl FakeGitClientConfig {
    /// Creates the default configuration ([`RepoUrlPolicy::Production`], system temp dir).
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

    /// Sets the directory under which checkouts are materialized.
    ///
    /// Point this at [`super::RepoCacheConfig::work_root`] to let the cache publish checkouts
    /// with an atomic same-filesystem `rename(2)`.
    #[must_use]
    pub fn with_work_root(mut self, work_root: impl Into<PathBuf>) -> Self {
        self.work_root = Some(work_root.into());
        self
    }
}

/// Mutable fixture state guarded by one mutex.
#[derive(Debug)]
struct FakeState {
    /// Immutable commit contents, keyed by commit SHA (`BTreeMap` => deterministic walk order).
    commits: BTreeMap<String, BTreeMap<String, String>>,
    /// Branch (`refs/heads/*`) tips.
    branches: BTreeMap<String, String>,
    /// Lightweight tag (`refs/tags/*`) targets.
    tags: BTreeMap<String, String>,
    /// `HEAD` state; `None` means "unborn" (`HEAD` does not resolve yet).
    head: Option<FakeHead>,
    /// URL policy enforced on every operation.
    url_policy: RepoUrlPolicy,
    /// Optional parent directory for materialized checkouts.
    work_root: Option<PathBuf>,
    /// `target_revision` of every `resolve_revision` call, in call order.
    resolve_log: Vec<String>,
    /// Requested SHA of every `checkout` call, in call order.
    checkout_log: Vec<String>,
    /// Queued `resolve_revision` failures, consumed front-to-back.
    resolve_faults: VecDeque<RepoError>,
    /// Queued `checkout` failures, consumed front-to-back.
    checkout_faults: VecDeque<RepoError>,
    /// Number of commits created so far; folded into the SHA so every commit is distinct.
    ordinal: u32,
}

impl FakeState {
    /// Returns the queue for `stage`.
    fn faults_mut(&mut self, stage: FakeStage) -> &mut VecDeque<RepoError> {
        match stage {
            FakeStage::Resolve => &mut self.resolve_faults,
            FakeStage::Checkout => &mut self.checkout_faults,
        }
    }

    /// Returns the queue for `stage`.
    fn faults(&self, stage: FakeStage) -> &VecDeque<RepoError> {
        match stage {
            FakeStage::Resolve => &self.resolve_faults,
            FakeStage::Checkout => &self.checkout_faults,
        }
    }
}

/// Deterministic, in-memory [`GitClient`] fixture for unit, contract, and integration tests.
///
/// See the [module documentation](self) for the design guarantees. Cloning is cheap and shares
/// the same fixture state.
#[derive(Clone)]
pub struct FakeGitClient {
    state: Arc<Mutex<FakeState>>,
}

impl Default for FakeGitClient {
    fn default() -> Self {
        Self::with_config(FakeGitClientConfig::default())
    }
}

impl fmt::Debug for FakeGitClient {
    /// Prints fixture *shape* only (never file bodies), and never blocks on the state mutex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("FakeGitClient");
        match self.state.try_lock() {
            Ok(state) => dbg
                .field("commits", &state.commits.len())
                .field("branches", &state.branches)
                .field("tags", &state.tags)
                .field("head", &state.head)
                .field("url_policy", &state.url_policy)
                .field("work_root", &state.work_root)
                .field("resolve_calls", &state.resolve_log.len())
                .field("checkout_calls", &state.checkout_log.len())
                .field("pending_resolve_faults", &state.resolve_faults.len())
                .field("pending_checkout_faults", &state.checkout_faults.len())
                .finish(),
            // Locked by another thread: report nothing that requires the state.
            Err(_) => dbg.finish_non_exhaustive(),
        }
    }
}

impl FakeGitClient {
    /// Creates an empty fixture with default configuration (no commits, unborn `HEAD`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty fixture with an explicit configuration.
    #[must_use]
    pub fn with_config(config: FakeGitClientConfig) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                commits: BTreeMap::new(),
                branches: BTreeMap::new(),
                tags: BTreeMap::new(),
                head: None,
                url_policy: config.url_policy,
                work_root: config.work_root,
                resolve_log: Vec::new(),
                checkout_log: Vec::new(),
                resolve_faults: VecDeque::new(),
                checkout_faults: VecDeque::new(),
                ordinal: 0,
            })),
        }
    }

    /// Returns a snapshot of the active configuration.
    #[must_use]
    pub fn config(&self) -> FakeGitClientConfig {
        let state = self.lock();
        FakeGitClientConfig {
            url_policy: state.url_policy,
            work_root: state.work_root.clone(),
        }
    }

    /// Appends a commit to `branch` containing `files` and returns its 40-character hex SHA.
    ///
    /// * Creating a branch: the first `add_commit` for a branch starts it (with an empty
    ///   parent); later calls advance the branch tip.
    /// * `HEAD` follows the branch of the *first* commit until it is moved explicitly with
    ///   [`Self::set_head_branch`] or [`Self::detach_head`].
    /// * Commits are immutable: previously returned SHAs keep resolving to their original
    ///   contents forever.
    /// * A commit is a **full tree snapshot** like Git, not a delta: it contains exactly
    ///   `files`, so a path omitted from a later commit is absent from that commit.
    /// * Duplicate paths collapse onto the last value (like a Git tree).
    /// * Paths are validated at checkout time, not here, so this stays infallible; a path that
    ///   escapes the checkout root fails the checkout with a terminal
    ///   [`RepoError::InvalidSource`] instead of writing outside it.
    ///
    /// The SHA is a pure function of `(parent, branch, call ordinal, files)`, so replaying the
    /// same sequence of calls on any machine reproduces the same SHAs.
    pub fn add_commit<I, K, V>(&self, branch: &str, files: I) -> String
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let files: BTreeMap<String, String> = files
            .into_iter()
            .map(|(path, body)| (path.into(), body.into()))
            .collect();

        let mut state = self.lock();
        let parent = state.branches.get(branch).cloned().unwrap_or_default();
        let ordinal = state.ordinal;
        let sha = commit_sha(&parent, branch, ordinal, &files);

        state.ordinal = state.ordinal.wrapping_add(1);
        state.commits.insert(sha.clone(), files);
        state.branches.insert(branch.to_owned(), sha.clone());
        if state.head.is_none() {
            state.head = Some(FakeHead::Branch(branch.to_owned()));
        }
        sha
    }

    /// Adds a lightweight tag pointing at `sha`.
    ///
    /// Annotated tags are tag *objects* peeled to a commit; they are covered by the
    /// `GixGitClient` integration tests, so the fake only models the peeled result.
    pub fn add_tag(&self, tag: impl Into<String>, sha: impl Into<String>) {
        let mut state = self.lock();
        state.tags.insert(tag.into(), sha.into());
    }

    /// Points `HEAD` at `branch` (a symbolic ref), like `git switch`.
    ///
    /// The branch does not have to exist yet; resolving `HEAD` before its first commit is a
    /// [`RepoError::RevisionNotFound`].
    pub fn set_head_branch(&self, branch: impl Into<String>) {
        let mut state = self.lock();
        state.head = Some(FakeHead::Branch(branch.into()));
    }

    /// Detaches `HEAD` at the known commit `sha`, like `git switch --detach`.
    ///
    /// The SHA is stored verbatim; `HEAD` only resolves successfully while `sha` is a commit
    /// this fixture still contains.
    pub fn detach_head(&self, sha: impl Into<String>) {
        let mut state = self.lock();
        state.head = Some(FakeHead::Detached(sha.into()));
    }

    /// Returns the current `HEAD` state, or `None` for an unborn `HEAD`.
    #[must_use]
    pub fn head(&self) -> Option<FakeHead> {
        self.lock().head.clone()
    }

    /// Returns the tip SHA of `branch`, or `None` when the branch does not exist.
    #[must_use]
    pub fn branch_tip(&self, branch: &str) -> Option<String> {
        self.lock().branches.get(branch).cloned()
    }

    /// Returns the target SHA of lightweight `tag`, or `None` when the tag does not exist.
    #[must_use]
    pub fn tag_target(&self, tag: &str) -> Option<String> {
        self.lock().tags.get(tag).cloned()
    }

    /// Returns a copy of the files stored in commit `sha`, or `None` for an unknown SHA.
    #[must_use]
    pub fn commit_files(&self, sha: &str) -> Option<BTreeMap<String, String>> {
        self.lock().commits.get(sha).cloned()
    }

    /// Returns the number of commits the fixture contains.
    #[must_use]
    pub fn commit_count(&self) -> usize {
        self.lock().commits.len()
    }

    /// Queues `error` for the next `stage` operation and returns `self` for chaining.
    ///
    /// Queued faults are consumed one per operation, front-to-back, *after* source validation:
    /// the injected error is returned exactly once, and the following call proceeds normally.
    ///
    /// Ordering inside an operation: [`GitSource::validate`] first, then the queued fault, then
    /// the commit/ref lookup. So an injected [`FakeStage::Checkout`] fault **masks** the lookup
    /// stage — checking out an unknown SHA with a queued fault yields the injected error, not
    /// [`RepoError::RevisionNotFound`] — and an injected [`FakeStage::Resolve`] fault masks
    /// resolution of an unknown or non-canonical revision the same way. This mirrors a real
    /// transport: a network outage happens before the server can say "no such ref".
    pub fn fail_next(&self, stage: FakeStage, error: RepoError) -> &Self {
        self.lock().faults_mut(stage).push_back(error);
        self
    }

    /// Queues every error in `errors` for `stage`, consumed in iteration order.
    pub fn fail_sequence(
        &self,
        stage: FakeStage,
        errors: impl IntoIterator<Item = RepoError>,
    ) -> &Self {
        {
            let mut state = self.lock();
            let queue = state.faults_mut(stage);
            queue.extend(errors);
        }
        self
    }

    /// Convenes the common "one transient failure, then success" retry script for `stage`.
    ///
    /// Equivalent to [`Self::fail_next`] with a single error; the readable name documents the
    /// intent at call sites that assert a retry-then-succeed loop. The error is expected to be
    /// retryable (`RepoError::is_retryable() == true`); the fake never reclassifies it.
    pub fn fail_once_then_succeed(&self, stage: FakeStage, error: RepoError) -> &Self {
        self.fail_next(stage, error)
    }

    /// Returns how many faults are still queued for `stage`.
    #[must_use]
    pub fn pending_faults(&self, stage: FakeStage) -> usize {
        self.lock().faults(stage).len()
    }

    /// Returns `true` when every queued fault for every stage has been consumed.
    #[must_use]
    pub fn faults_exhausted(&self) -> bool {
        let state = self.lock();
        state.resolve_faults.is_empty() && state.checkout_faults.is_empty()
    }

    /// Drops every queued fault for `stage`, so a test can recover a fixture between phases.
    pub fn clear_faults(&self, stage: FakeStage) {
        self.lock().faults_mut(stage).clear();
    }

    /// Returns how many [`GitClient::resolve_revision`] calls were made, including failed ones.
    #[must_use]
    pub fn resolve_calls(&self) -> usize {
        self.lock().resolve_log.len()
    }

    /// Returns how many [`GitClient::checkout`] calls were made, including failed ones.
    #[must_use]
    pub fn checkout_calls(&self) -> usize {
        self.lock().checkout_log.len()
    }

    /// Returns the `target_revision` of every resolve call, in call order.
    #[must_use]
    pub fn resolve_log(&self) -> Vec<String> {
        self.lock().resolve_log.clone()
    }

    /// Returns the requested SHA of every checkout call, in call order.
    #[must_use]
    pub fn checkout_log(&self) -> Vec<String> {
        self.lock().checkout_log.clone()
    }

    /// Clears the resolve/checkout call logs (faults and commits are untouched).
    pub fn reset_call_log(&self) {
        let mut state = self.lock();
        state.resolve_log.clear();
        state.checkout_log.clear();
    }

    /// Locks the fixture state, recovering from a poisoned mutex instead of panicking.
    ///
    /// A test harness must never turn one failing assertion (which poisons the mutex) into a
    /// cascade of unrelated panics in concurrent tasks.
    fn lock(&self) -> MutexGuard<'_, FakeState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Records one resolve call.
    fn record_resolve(&self, revision: &str) {
        self.lock().resolve_log.push(revision.to_owned());
    }

    /// Records one checkout call.
    fn record_checkout(&self, sha: &str) {
        self.lock().checkout_log.push(sha.to_owned());
    }
}

impl GitClient for FakeGitClient {
    fn resolve_revision<'a>(
        &'a self,
        src: &'a GitSource,
        _creds: &'a RepoCredentials,
    ) -> RepoFuture<'a, ResolvedRevision> {
        Box::pin(async move {
            self.record_resolve(&src.target_revision);

            // Validation first, exactly like `GixGitClient`: a rejected source never consumes a
            // queued fault, so tests can rely on the origin of the error they observe.
            let policy = self.config().url_policy;
            src.validate(policy)?;

            let mut state = self.lock();
            if let Some(err) = state.resolve_faults.pop_front() {
                return Err(err);
            }
            let commit_sha = resolve_sha(&state, &src.target_revision)?;
            drop(state);

            Ok(ResolvedRevision {
                commit_sha,
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
            self.record_checkout(sha);

            let policy = self.config().url_policy;
            src.validate(policy)?;
            validate_commit_sha(sha)?;

            let (work_root, files) = {
                let mut state = self.lock();
                if let Some(err) = state.checkout_faults.pop_front() {
                    return Err(err);
                }
                let files = state.commits.get(sha).map(|files| {
                    files
                        .iter()
                        .map(|(path, body)| (path.clone(), body.clone()))
                        .collect::<Vec<(String, String)>>()
                });
                (state.work_root.clone(), files)
            };

            let Some(files) = files else {
                return Err(RepoError::RevisionNotFound {
                    revision: sha.to_owned(),
                });
            };

            // Filesystem work is blocking: never run it on a Tokio worker (AGENTS.md).
            let sha_owned = sha.to_owned();
            tokio::task::spawn_blocking(move || {
                materialize_worktree(work_root.as_deref(), &sha_owned, &files)
            })
            .await
            .map_err(|join_err| RepoError::RepositoryError {
                message: format!("fake git checkout task failed: {join_err}"),
            })?
        })
    }
}

/// Resolves `revision` against the fixture, mirroring `GixGitClient`'s lookup order.
///
/// Supported: `refs/heads/<branch>`, `refs/tags/<tag>`, `HEAD`, full 40-character hex commit
/// SHAs, and the short `branch` / `tag` names used by `target_revision`. Anything else —
/// including another `refs/...` namespace or a commit the fixture does not contain — is a
/// terminal [`RepoError::RevisionNotFound`].
///
/// Every path that produces a SHA — ref-derived or literal — goes through the *same* predicate:
/// the target must be canonical (`validate_commit_sha`) **and** present in `state.commits`.
/// A ref can therefore never resolve to a SHA that `checkout` would subsequently reject, so
/// [`ResolvedRevision::commit_sha`] is always a usable cache key.
fn resolve_sha(state: &FakeState, revision: &str) -> Result<String, RepoError> {
    let not_found = || RepoError::RevisionNotFound {
        revision: revision.to_owned(),
    };

    // The one accepted shape of a resolved target: canonical hex AND a commit we hold.
    let commit_target = |target: Option<&String>| match target {
        Some(target)
            if validate_commit_sha(target).is_ok() && state.commits.contains_key(target) =>
        {
            Ok(target.clone())
        }
        _ => Err(not_found()),
    };

    if let Some(branch) = revision.strip_prefix("refs/heads/") {
        return if branch.is_empty() {
            Err(not_found())
        } else {
            commit_target(state.branches.get(branch))
        };
    }
    if let Some(tag) = revision.strip_prefix("refs/tags/") {
        return if tag.is_empty() {
            Err(not_found())
        } else {
            commit_target(state.tags.get(tag))
        };
    }
    if revision.starts_with("refs/") {
        return Err(not_found());
    }
    if revision == "HEAD" {
        return match &state.head {
            Some(FakeHead::Branch(branch)) => commit_target(state.branches.get(branch)),
            Some(FakeHead::Detached(sha)) => commit_target(Some(sha)),
            None => Err(not_found()),
        };
    }
    if validate_commit_sha(revision).is_ok() {
        return if state.commits.contains_key(revision) {
            Ok(revision.to_owned())
        } else {
            Err(not_found())
        };
    }
    // Short names: branches win over tags, matching Git's own `refs/heads` preference. An empty
    // name is never a ref (the fixture does not create one, and it must not resolve even if a
    // caller stores `add_tag("", …)`), so this stays a terminal `RevisionNotFound`.
    if revision.is_empty() {
        return Err(not_found());
    }
    commit_target(
        state
            .branches
            .get(revision)
            .or_else(|| state.tags.get(revision)),
    )
}

/// Derives the deterministic 40-character lowercase hex SHA of one fake commit.
///
/// The digest covers the parent SHA, the branch, the call ordinal and every `(path, body)`
/// pair in sorted order, so distinct commits never collide in practice while replays produce
/// identical SHAs. `16 + 16 + 8 = 40` hex characters, always lowercase.
fn commit_sha(
    parent: &str,
    branch: &str,
    ordinal: u32,
    files: &BTreeMap<String, String>,
) -> String {
    let mut material: Vec<u8> = Vec::new();
    material.extend_from_slice(parent.as_bytes());
    material.push(0);
    material.extend_from_slice(branch.as_bytes());
    material.push(0);
    material.extend_from_slice(&ordinal.to_le_bytes());
    for (path, body) in files {
        material.extend_from_slice(path.as_bytes());
        material.push(0);
        material.extend_from_slice(body.as_bytes());
        material.push(0);
    }

    format!(
        "{:016x}{:016x}{ordinal:08x}",
        fnv1a64(FNV_OFFSET_BASIS, &material),
        fnv1a64(SECONDARY_SEED, &material),
    )
}

/// FNV-1a 64-bit hash of `bytes`, seeded with `seed`.
fn fnv1a64(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Writes one commit's files into a fresh temporary directory (blocking; runs off the reactor).
///
/// The returned [`RepoCheckout`] holds the [`TempDir`] as its lease, so the directory is
/// deleted as soon as the handle is dropped — and, when a [`super::RepoCache`] renames the
/// directory into its own layout, the rename wins and no directory is left behind.
fn materialize_worktree(
    work_root: Option<&Path>,
    sha: &str,
    files: &[(String, String)],
) -> Result<RepoCheckout, RepoError> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(TEMP_PREFIX);
    let dir = match work_root {
        Some(root) => {
            std::fs::create_dir_all(root).map_err(|source| RepoError::Io {
                context: format!("creating fake git work_root '{}'", root.display()),
                source,
            })?;
            builder.tempdir_in(root).map_err(|source| RepoError::Io {
                context: format!("creating fake checkout under '{}'", root.display()),
                source,
            })?
        }
        None => builder.tempdir().map_err(|source| RepoError::Io {
            context: "creating fake checkout temp dir".to_owned(),
            source,
        })?,
    };

    for (relative, body) in files {
        let path = join_relative(dir.path(), relative)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| RepoError::Io {
                context: format!("creating fake checkout directory '{}'", parent.display()),
                source,
            })?;
        }
        std::fs::write(&path, body).map_err(|source| RepoError::Io {
            context: format!("writing fake checkout file '{}'", path.display()),
            source,
        })?;
    }

    let root = dir.path().to_path_buf();
    Ok(RepoCheckout::with_lease(root, sha, Arc::new(dir)))
}

/// Joins a commit-relative file path onto `root`, refusing any component that could escape it.
///
/// Commit paths are attacker-controlled in production; even though a fake commit is authored by
/// a test, an escaping path must fail loudly (terminal [`RepoError::InvalidSource`]) rather than
/// write outside the checkout root.
fn join_relative(root: &Path, relative: &str) -> Result<PathBuf, RepoError> {
    let invalid = |reason: &str| RepoError::InvalidSource {
        reason: format!("fake commit file path '{relative}': {reason}"),
    };

    if relative.is_empty() {
        return Err(invalid("must not be empty"));
    }
    if relative.contains('\\') {
        return Err(invalid("must not contain '\\'"));
    }
    if relative.chars().any(char::is_control) {
        return Err(invalid("must not contain control characters"));
    }

    let mut path = PathBuf::from(root);
    let mut components = 0usize;
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => {
                path.push(part);
                components += 1;
            }
            Component::ParentDir => {
                return Err(invalid("must not contain '..' traversal segments"));
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(invalid("must be a relative path"));
            }
            Component::CurDir => {}
        }
    }
    if components == 0 {
        return Err(invalid("must name a file"));
    }

    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// A source the default [`RepoUrlPolicy::Production`] accepts.
    fn source(revision: &str) -> GitSource {
        GitSource::new(
            "https://github.com/ferris-cd/monorepo.git",
            revision,
            "apps",
        )
    }

    /// Convenience wrapper: resolve `revision` through the [`GitClient`] trait.
    async fn resolve(
        client: &FakeGitClient,
        revision: &str,
    ) -> Result<ResolvedRevision, RepoError> {
        client
            .resolve_revision(&source(revision), &RepoCredentials::Anonymous)
            .await
    }

    /// Convenience wrapper: check out `sha` through the [`GitClient`] trait.
    async fn checkout(client: &FakeGitClient, sha: &str) -> Result<RepoCheckout, RepoError> {
        client
            .checkout(&source("main"), sha, &RepoCredentials::Anonymous)
            .await
    }

    fn read(root: &Path, relative: &str) -> String {
        std::fs::read_to_string(root.join(relative))
            .unwrap_or_else(|err| panic!("reading {relative} under {}: {err}", root.display()))
    }

    /// Builds a two-branch fixture: `main` has two commits, `release` one.
    ///
    /// Returns the client and the three commit SHAs in creation order.
    fn fixture() -> (FakeGitClient, [String; 3]) {
        let client = FakeGitClient::new();
        let first = client.add_commit(
            "main",
            [
                ("README.md", "version=1\n"),
                ("apps/base/deployment.yaml", "kind: Deployment\n"),
            ],
        );
        let second = client.add_commit("main", [("README.md", "version=2\n")]);
        let release = client.add_commit("release", [("README.md", "version=release\n")]);
        (client, [first, second, release])
    }

    #[tokio::test]
    async fn resolves_branch_tag_head_sha_and_rejects_unknown_refs() {
        let client = FakeGitClient::new();
        let c1 = client.add_commit("main", [("README.md", "version=1\n")]);
        let c2 = client.add_commit("main", [("README.md", "version=2\n")]);
        client.add_tag("v1.0.0", c1.clone());

        // Full 40-character lowercase hex, accepted by the shared validator.
        for sha in [&c1, &c2] {
            assert_eq!(sha.len(), 40, "fake SHAs must be 40 hex characters: {sha}");
            assert!(
                sha.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "fake SHAs must be lowercase hex: {sha}"
            );
            validate_commit_sha(sha).expect("fake SHAs must satisfy validate_commit_sha");
        }
        assert_ne!(c1, c2, "distinct commits must have distinct SHAs");

        for (revision, expected) in [
            ("main", &c2),
            ("refs/heads/main", &c2),
            ("HEAD", &c2),
            ("refs/tags/v1.0.0", &c1),
            ("v1.0.0", &c1),
            (&c1, &c1),
            (&c2, &c2),
        ] {
            let resolved = resolve(&client, revision)
                .await
                .unwrap_or_else(|err| panic!("resolving {revision} must succeed: {err}"));
            assert_eq!(&resolved.commit_sha, expected, "wrong SHA for {revision}");
            assert_eq!(
                resolved.requested_ref, revision,
                "requested_ref must echo the caller's revision"
            );
        }

        // A lightweight tag resolves through the tag namespace only when it exists.
        assert_eq!(client.tag_target("v1.0.0").as_deref(), Some(c1.as_str()));
        assert_eq!(client.branch_tip("main").as_deref(), Some(c2.as_str()));
        assert_eq!(client.branch_tip("missing"), None);

        // Detached HEAD resolves to the exact commit it points at.
        client.detach_head(c1.clone());
        assert_eq!(client.head(), Some(FakeHead::Detached(c1.clone())));
        assert_eq!(
            resolve(&client, "HEAD").await.expect("detached").commit_sha,
            c1
        );

        // Unknown refs, unknown SHAs, and unknown ref namespaces are terminal.
        for revision in [
            "does-not-exist",
            "refs/heads/does-not-exist",
            "refs/tags/v9.9.9",
            "refs/remotes/origin/main",
            "0123456789abcdef0123456789abcdef01234567",
        ] {
            let err = resolve(&client, revision)
                .await
                .expect_err("unknown revision must fail");
            match &err {
                RepoError::RevisionNotFound { revision: got } => {
                    assert_eq!(got, revision, "error must name the offending revision");
                }
                other => panic!("expected RevisionNotFound for {revision}, got {other:?}"),
            }
            assert!(!err.is_retryable(), "unknown revision must be terminal");
        }

        // An unborn HEAD (no commit yet) never resolves.
        let empty = FakeGitClient::new();
        assert_eq!(empty.head(), None);
        let err = resolve(&empty, "HEAD")
            .await
            .expect_err("unborn HEAD must not resolve");
        assert!(matches!(err, RepoError::RevisionNotFound { .. }));

        // A detached HEAD pointing at a commit the fixture does not hold is unknown too.
        empty.detach_head("0123456789abcdef0123456789abcdef01234567");
        assert!(matches!(
            resolve(&empty, "HEAD").await,
            Err(RepoError::RevisionNotFound { .. })
        ));
    }

    #[tokio::test]
    async fn switching_branches_yields_distinct_content_and_history_stays_checkable() {
        let (client, [first, main_tip, release_tip]) = fixture();
        assert_eq!(client.branch_tip("main"), Some(main_tip.clone()));
        assert_eq!(client.branch_tip("release"), Some(release_tip.clone()));

        // `HEAD` followed the first commit's branch; switching it changes what `HEAD` means.
        assert_eq!(client.head(), Some(FakeHead::Branch("main".to_owned())));
        client.set_head_branch("release");
        assert_eq!(
            resolve(&client, "HEAD").await.expect("HEAD").commit_sha,
            release_tip
        );
        client.set_head_branch("main");
        assert_eq!(
            resolve(&client, "HEAD").await.expect("HEAD").commit_sha,
            main_tip
        );

        let on_main = checkout(&client, &main_tip)
            .await
            .expect("checkout main tip");
        assert_eq!(read(on_main.root_dir(), "README.md"), "version=2\n");
        assert!(
            !on_main.root_dir().join("apps").exists(),
            "a commit is a full tree snapshot (like Git), so a path it omits is absent"
        );

        let on_release = checkout(&client, &release_tip).await.expect("release");
        assert_eq!(
            read(on_release.root_dir(), "README.md"),
            "version=release\n"
        );
        assert_ne!(
            on_main.root_dir(),
            on_release.root_dir(),
            "different commits must materialize in different directories"
        );

        // The pre-tip commit is still addressable: history is immutable, not a moving pointer.
        let historical = checkout(&client, &first).await.expect("historical commit");
        assert_eq!(read(historical.root_dir(), "README.md"), "version=1\n");
        assert_eq!(
            client.commit_files(&first).expect("known commit"),
            BTreeMap::from([
                ("README.md".to_owned(), "version=1\n".to_owned()),
                (
                    "apps/base/deployment.yaml".to_owned(),
                    "kind: Deployment\n".to_owned()
                ),
            ]),
            "advancing a branch must never rewrite an earlier commit"
        );
        assert_eq!(client.commit_count(), 3);
        assert_eq!(
            client.checkout_calls(),
            3,
            "every checkout must be recorded"
        );
    }

    #[tokio::test]
    async fn checkout_matches_commit_without_git_metadata_and_drop_cleans_up() {
        let work_root = tempfile::tempdir().expect("create work root");
        let client =
            FakeGitClient::with_config(FakeGitClientConfig::new().with_work_root(work_root.path()));
        let sha = client.add_commit(
            "main",
            [
                ("README.md", "version=1\n"),
                ("apps/prod/kustomization.yaml", "resources: []\n"),
            ],
        );

        let checkout = checkout(&client, &sha).await.expect("checkout");
        assert_eq!(checkout.commit_sha(), sha);
        // Materialized under the configured work root (so a cache can rename it atomically).
        assert!(
            checkout.root_dir().starts_with(work_root.path()),
            "checkout {} must live under work_root {}",
            checkout.root_dir().display(),
            work_root.path().display()
        );
        assert_eq!(read(checkout.root_dir(), "README.md"), "version=1\n");
        assert_eq!(
            read(checkout.root_dir(), "apps/prod/kustomization.yaml"),
            "resources: []\n"
        );
        // Never fabricate Git metadata: renderers must not see a `.git` directory.
        assert!(!checkout.root_dir().join(".git").exists());

        let root = checkout.root_dir().to_path_buf();
        assert!(root.is_dir());
        drop(checkout);
        assert!(
            !root.exists(),
            "dropping the RepoCheckout must delete its temporary directory"
        );
    }

    #[tokio::test]
    async fn transient_failure_then_success_and_terminal_failures_per_stage() {
        let (client, [_first, tip, _release]) = fixture();

        // --- Resolve: transient (retryable) failure, then success. ---
        client
            .fail_once_then_succeed(
                FakeStage::Resolve,
                RepoError::Network {
                    message: "connection reset by peer".to_owned(),
                },
            )
            .fail_next(
                FakeStage::Resolve,
                RepoError::RemoteServerError {
                    status: Some(503),
                    message: "service unavailable".to_owned(),
                },
            )
            .fail_next(
                FakeStage::Resolve,
                RepoError::Timeout {
                    message: "fetch timed out".to_owned(),
                },
            );
        assert_eq!(client.pending_faults(FakeStage::Resolve), 3);

        for expected in ["connection reset", "503", "timed out"] {
            let err = resolve(&client, "main")
                .await
                .expect_err("queued resolve fault must fire");
            assert!(
                err.is_retryable(),
                "a transient outage must be classified retryable: {err}"
            );
            assert!(
                err.to_string().contains(expected),
                "unexpected injected error {err}"
            );
        }
        assert!(client.faults_exhausted(), "the retry queue must be drained");
        assert_eq!(
            resolve(&client, "main")
                .await
                .expect("retry succeeds")
                .commit_sha,
            tip,
            "the retry after a transient outage must succeed"
        );

        // --- Resolve: terminal (non-retryable) failures. ---
        for terminal in [
            RepoError::RevisionNotFound {
                revision: "main".to_owned(),
            },
            RepoError::AuthFailed {
                reason: "HTTP 401".to_owned(),
            },
        ] {
            let label = format!("{terminal}");
            client.fail_next(FakeStage::Resolve, terminal);
            let err = resolve(&client, "main")
                .await
                .expect_err("queued terminal fault must fire");
            assert!(
                !err.is_retryable(),
                "terminal failure must not be retryable: {err} ({label})"
            );
            assert!(client.faults_exhausted());
            assert_eq!(
                resolve(&client, "main")
                    .await
                    .expect("next call is clean")
                    .commit_sha,
                tip
            );
        }

        // --- Checkout: transient (retryable) failure, then success. ---
        client.fail_once_then_succeed(
            FakeStage::Checkout,
            RepoError::Network {
                message: "dial tcp: connection refused".to_owned(),
            },
        );
        let err = checkout(&client, &tip)
            .await
            .expect_err("queued checkout fault must fire");
        assert!(err.is_retryable(), "transient checkout failure: {err}");
        assert_eq!(client.pending_faults(FakeStage::Checkout), 0);
        assert!(
            client.faults_exhausted(),
            "checkout faults must be a separate queue from resolve faults"
        );
        let materialized = checkout(&client, &tip).await.expect("retry succeeds");
        assert_eq!(read(materialized.root_dir(), "README.md"), "version=2\n");

        // --- Checkout: terminal (non-retryable) failure. ---
        client.fail_next(
            FakeStage::Checkout,
            RepoError::UnsafeSymlink {
                path: PathBuf::from("values.yaml"),
                target: PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token"),
                reason: "symlink target escapes the checkout root".to_owned(),
            },
        );
        let err = checkout(&client, &tip)
            .await
            .expect_err("queued terminal checkout fault must fire");
        assert!(
            !err.is_retryable(),
            "symlink escape must be terminal: {err}"
        );
        assert!(matches!(err, RepoError::UnsafeSymlink { .. }));
        assert!(client.faults_exhausted());
        let after = checkout(&client, &tip).await.expect("next call is clean");
        assert_eq!(after.commit_sha(), tip);

        // Faults are recorded even though they failed, and stage counters stay independent.
        assert_eq!(client.checkout_calls(), 4);
        assert_eq!(client.resolve_calls(), 8);

        // `clear_faults` drops leftovers so a fixture can be reused between phases.
        client
            .fail_next(
                FakeStage::Resolve,
                RepoError::Network {
                    message: "leftover".to_owned(),
                },
            )
            .fail_next(
                FakeStage::Checkout,
                RepoError::Network {
                    message: "leftover".to_owned(),
                },
            );
        assert!(!client.faults_exhausted());
        client.clear_faults(FakeStage::Resolve);
        assert_eq!(client.pending_faults(FakeStage::Resolve), 0);
        assert!(
            !client.faults_exhausted(),
            "checkout faults must still be queued"
        );
        client.clear_faults(FakeStage::Checkout);
        assert!(client.faults_exhausted());
        assert_eq!(
            resolve(&client, "main")
                .await
                .expect("clean resolve")
                .commit_sha,
            tip
        );
    }

    #[tokio::test]
    async fn source_validation_runs_before_faults_and_does_not_consume_them() {
        // Production policy rejects local paths, exactly like `GixGitClient`.
        let client = FakeGitClient::new();
        client.add_commit("main", [("README.md", "version=1\n")]);
        client.fail_once_then_succeed(
            FakeStage::Resolve,
            RepoError::Network {
                message: "would be retried".to_owned(),
            },
        );

        let local = GitSource::new("file:///tmp/monorepo", "main", "");
        let err = client
            .resolve_revision(&local, &RepoCredentials::Anonymous)
            .await
            .expect_err("file:// must be rejected under the production policy");
        assert!(
            matches!(err, RepoError::InvalidUrl { .. }),
            "expected InvalidUrl, got {err:?}"
        );
        assert!(!err.is_retryable());
        assert_eq!(
            client.pending_faults(FakeStage::Resolve),
            1,
            "a rejected source must not consume a queued fault"
        );

        let bad_revision = GitSource::new("https://github.com/ferris-cd/monorepo.git", "", "");
        let err = client
            .resolve_revision(&bad_revision, &RepoCredentials::Anonymous)
            .await
            .expect_err("empty target_revision must be rejected");
        assert!(matches!(err, RepoError::InvalidSource { .. }));
        assert_eq!(client.pending_faults(FakeStage::Resolve), 1);

        // The same source is accepted once the policy allows local paths.
        let local_client = FakeGitClient::with_config(
            FakeGitClientConfig::new().with_url_policy(RepoUrlPolicy::AllowLocal),
        );
        let sha = local_client.add_commit("main", [("README.md", "version=1\n")]);
        let resolved = local_client
            .resolve_revision(&local, &RepoCredentials::Anonymous)
            .await
            .expect("AllowLocal must accept file:// sources");
        assert_eq!(resolved.commit_sha, sha);

        // Invalid SHAs are rejected before any filesystem work.
        let err = checkout(&client, "NOT-A-SHA")
            .await
            .expect_err("invalid SHA must be rejected");
        assert!(matches!(err, RepoError::InvalidRevision { .. }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_checkouts_of_shared_fixture_do_not_corrupt_or_panic() {
        let work_root = tempfile::tempdir().expect("create work root");
        let client =
            FakeGitClient::with_config(FakeGitClientConfig::new().with_work_root(work_root.path()));
        let c1 = client.add_commit("main", [("README.md", "version=1\n")]);
        let c2 = client.add_commit("main", [("README.md", "version=2\n")]);
        let c3 = client.add_commit(
            "release",
            [("README.md", "version=3\n"), ("release-only.txt", "3\n")],
        );
        client.add_tag("stable", c1.clone());

        let commits = [
            (c1, "version=1\n", false),
            (c2, "version=2\n", false),
            (c3, "version=3\n", true),
        ];

        let mut tasks = Vec::with_capacity(12);
        for index in 0..12usize {
            let client = client.clone();
            let (sha, expected, has_release_file) = commits[index % commits.len()].clone();
            tasks.push(tokio::spawn(async move {
                let checkout = client
                    .checkout(&source("main"), &sha, &RepoCredentials::Anonymous)
                    .await
                    .unwrap_or_else(|err| panic!("concurrent checkout of {sha} failed: {err}"));
                assert_eq!(checkout.commit_sha(), sha);
                // Read every file while the lease is held: a torn tree would show as missing or
                // truncated content here.
                let readme = read(checkout.root_dir(), "README.md");
                let has_file = checkout.root_dir().join("release-only.txt").is_file();
                (sha, expected, has_release_file, readme, has_file, checkout)
            }));
        }

        let mut roots: BTreeSet<PathBuf> = BTreeSet::new();
        let mut held = Vec::new();
        for task in tasks {
            let (sha, expected, has_release_file, readme, has_file, checkout) =
                task.await.expect("checkout task must not panic");
            assert_eq!(readme, expected, "corrupt README for commit {sha}");
            assert_eq!(
                has_file, has_release_file,
                "unexpected release-only.txt presence for commit {sha}"
            );
            // Every handle is still alive here, so distinct handles must own distinct roots.
            assert!(
                roots.insert(checkout.root_dir().to_path_buf()),
                "two live checkouts share the directory {}",
                checkout.root_dir().display()
            );
            held.push(checkout);
        }

        assert_eq!(roots.len(), 12, "each checkout must own its own directory");
        assert_eq!(client.checkout_calls(), 12);
        assert!(client.faults_exhausted());
        drop(held);
    }

    #[tokio::test]
    async fn works_through_arc_dyn_git_client() {
        let fake = FakeGitClient::new();
        let sha = fake.add_commit("main", [("README.md", "version=1\n")]);
        fake.add_tag("v1", sha.clone());
        let client: Arc<dyn GitClient> = Arc::new(fake.clone());

        let resolved = client
            .resolve_revision(&source("main"), &RepoCredentials::Anonymous)
            .await
            .expect("resolve through Arc<dyn GitClient>");
        assert_eq!(resolved.commit_sha, sha);
        let tagged = client
            .resolve_revision(&source("v1"), &RepoCredentials::Anonymous)
            .await
            .expect("tag resolve through Arc<dyn GitClient>");
        assert_eq!(tagged.commit_sha, sha);

        let checkout = client
            .checkout(&source("main"), &sha, &RepoCredentials::Anonymous)
            .await
            .expect("checkout through Arc<dyn GitClient>");
        assert_eq!(read(checkout.root_dir(), "README.md"), "version=1\n");

        // Calls made through the trait object are recorded on the shared fixture state.
        assert_eq!(fake.resolve_calls(), 2);
        assert_eq!(fake.checkout_calls(), 1);
        assert_eq!(fake.resolve_log(), vec!["main".to_owned(), "v1".to_owned()]);
        assert_eq!(fake.checkout_log(), vec![sha]);

        fake.reset_call_log();
        assert_eq!(fake.resolve_calls(), 0);
        assert_eq!(fake.checkout_calls(), 0);

        // `Debug` reports fixture shape only and never blocks (a lock is not held here).
        let dbg = format!("{fake:?}");
        assert!(dbg.contains("commits: 1"), "unexpected Debug output: {dbg}");
        assert!(dbg.contains("head:"), "unexpected Debug output: {dbg}");
        assert!(
            !dbg.contains("version=1"),
            "Debug must not print file bodies"
        );
    }

    #[tokio::test]
    async fn escaping_commit_path_is_rejected_as_terminal_error() {
        let work_root = tempfile::tempdir().expect("create work root");
        let client =
            FakeGitClient::with_config(FakeGitClientConfig::new().with_work_root(work_root.path()));
        // The checkout root is `<work_root>/ferriscd-fake-*`, so `../escaped.txt` would land at
        // exactly `<work_root>/escaped.txt` — that is the path the assertion must watch. (An
        // unrelated sandbox directory would make this test vacuous.)
        let escape = work_root.path().join("escaped.txt");
        let sha = client.add_commit(
            "main",
            [
                ("README.md", "version=1\n"),
                ("../escaped.txt", "escaped\n"),
            ],
        );

        let err = checkout(&client, &sha)
            .await
            .expect_err("an escaping commit path must fail the checkout");
        assert!(
            matches!(err, RepoError::InvalidSource { .. }),
            "expected InvalidSource, got {err:?}"
        );
        assert!(!err.is_retryable());
        assert!(
            !escape.exists(),
            "the fake must never write outside the checkout root ({})",
            escape.display()
        );
        // No sibling escape either: nothing at all outside a `ferriscd-fake-*` directory.
        let stray: Vec<String> = std::fs::read_dir(work_root.path())
            .expect("read work root")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with(TEMP_PREFIX))
            .collect();
        assert!(
            stray.is_empty(),
            "a failed checkout must not leave anything outside its own temp dir: {stray:?}"
        );
        // The failed checkout's temp dir is released with its `TempDir`; if a platform kept it
        // around, it may only hold the non-escaping file that was written before it.
        for entry in std::fs::read_dir(work_root.path())
            .expect("read work root")
            .flatten()
        {
            if !entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
                continue;
            }
            let mut files: Vec<String> = std::fs::read_dir(entry.path())
                .expect("read checkout root")
                .flatten()
                .map(|file| file.file_name().to_string_lossy().into_owned())
                .collect();
            files.sort();
            assert!(
                files.iter().all(|name| name == "README.md"),
                "a rejected checkout must not contain escaping entries: {files:?}"
            );
        }

        // An absolute path is rejected with the same terminal classification.
        let absolute = client.add_commit("main", [("/etc/passwd", "x\n")]);
        let err = checkout(&client, &absolute)
            .await
            .expect_err("an absolute commit path must fail the checkout");
        assert!(matches!(err, RepoError::InvalidSource { .. }));
    }

    #[test]
    fn commit_shas_are_deterministic_across_clients() {
        let script = |client: &FakeGitClient| {
            let first = client.add_commit("main", [("README.md", "one\n")]);
            let second = client.add_commit(
                "main",
                [
                    ("README.md", "two\n"),
                    ("apps/base.yaml", "kind: ConfigMap\n"),
                ],
            );
            let feature = client.add_commit("feature", [("README.md", "one\n")]);
            [first, second, feature]
        };

        let first = script(&FakeGitClient::new());
        let second = script(&FakeGitClient::new());
        assert_eq!(
            first, second,
            "replaying the same commit script must reproduce the same SHAs"
        );
        assert_eq!(first.iter().collect::<BTreeSet<_>>().len(), 3);

        // Branch tips follow the script and never rewrite history.
        let client = FakeGitClient::new();
        let shas = script(&client);
        assert_eq!(client.branch_tip("main").as_deref(), Some(shas[1].as_str()));
        assert_eq!(
            client.branch_tip("feature").as_deref(),
            Some(shas[2].as_str())
        );
        assert_eq!(client.commit_count(), 3);
        assert_eq!(
            client.commit_files(&shas[0]).expect("first commit"),
            BTreeMap::from([("README.md".to_owned(), "one\n".to_owned())]),
            "an earlier commit must keep its original content"
        );
    }

    #[tokio::test]
    async fn refs_pointing_at_non_canonical_or_unknown_commits_are_terminal_not_found() {
        let client = FakeGitClient::new();
        let sha = client.add_commit("main", [("README.md", "version=1\n")]);

        // A stored tag target that is not a commit at all, and one that is well-formed but
        // absent from the fixture. Both must fail *terminally* through every tag-looking path
        // instead of being echoed back as a `ResolvedRevision`.
        client.add_tag("v-bogus", "not-a-sha");
        client.add_tag("v-ghost", "0123456789abcdef0123456789abcdef01234567");
        // An empty ref name must never resolve either, however it was stored.
        client.add_tag("", sha.clone());

        for revision in [
            "v-bogus",
            "refs/tags/v-bogus",
            "v-ghost",
            "refs/tags/v-ghost",
        ] {
            let err = resolve(&client, revision)
                .await
                .expect_err("a ref with a non-canonical or absent target must not resolve");
            match &err {
                RepoError::RevisionNotFound { revision: got } => assert_eq!(
                    got, revision,
                    "the error must name the revision the caller asked for"
                ),
                other => panic!("expected RevisionNotFound for {revision}, got {other:?}"),
            }
            assert!(
                !err.is_retryable(),
                "an unresolvable ref target must be terminal: {err}"
            );
        }

        // An empty ref name is already rejected by `GitSource::validate` on the public path, and
        // the resolver refuses it independently (defense in depth, even with `add_tag("", …)`
        // stored), so a stale/oddly-stored fixture cannot leak a commit through it.
        let err = resolve(&client, "refs/tags/")
            .await
            .expect_err("an empty ref name must not resolve");
        assert!(
            !err.is_retryable(),
            "empty ref name must be terminal: {err}"
        );
        {
            let state = client.lock();
            for revision in ["refs/tags/", "refs/heads/", ""] {
                let err = resolve_sha(&state, revision)
                    .expect_err("an empty ref name must never resolve to a commit");
                assert!(
                    matches!(err, RepoError::RevisionNotFound { .. }),
                    "expected RevisionNotFound for {revision:?}, got {err:?}"
                );
            }
        }

        // The stored-but-unusable targets are still visible through the inspection helpers, so
        // the failure is provably about resolution, not about the tag having been dropped.
        assert_eq!(client.tag_target("v-bogus").as_deref(), Some("not-a-sha"));
        assert_eq!(
            client.tag_target("v-ghost").as_deref(),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        // A well-formed ref still resolves, and so does the commit it points at.
        assert_eq!(
            resolve(&client, "refs/heads/main")
                .await
                .expect("valid branch")
                .commit_sha,
            sha
        );
    }
}
