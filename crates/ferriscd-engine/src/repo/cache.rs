//! Per-repository concurrency lock and commit-keyed immutable worktree cache.
//!
//! Multiple `Application` resources frequently point at the same monorepo — often at
//! different commits or manifest sub-paths. Sharing one mutable scratch directory
//! between reconciles causes races and corrupted checkouts, so this module provides:
//!
//! * a **per-repository async mutex** (keyed by a normalized repository URL) that
//!   serializes all fetching/materialization work for one repository,
//! * **commit-keyed immutable worktrees** materialized with an atomic
//!   *write-to-temp-directory* + *rename* sequence, so a concurrent reader can never
//!   observe a partially written checkout,
//! * **verification before publication**: a renamed tree is sanitized by
//!   [`sanitize_worktree`] while the cache entry is still unpublished (`Materializing`), and
//!   only a verified tree ever becomes `Ready`, so no lock-free cache hit can lease an
//!   un-sanitized tree,
//! * **RAII ref-counted leases** so garbage collection never deletes a directory that
//!   is still held by an in-flight reconcile, and
//! * **bounded LRU / TTL garbage collection** (`max_entries`, `max_age`).
//!
//! The cache delegates the actual Git work to an injected [`GitClient`]; it only owns
//! the lock, the directory layout, and the refcounting.
//!
//! # Scope note: the persistent per-URL bare mirror lives in the client, not here
//!
//! [`RepoCache`] provides exactly two things: the per-repository async lock and the
//! commit-keyed worktree cache. The injected [`GitClient`] owns the acquisition backend; the
//! `gix`-backed [`super::GixGitClient`] maintains a **persistent per-URL bare mirror / object
//! store** (see [`super::mirror`]) so repeat materializations of one monorepo do not re-fetch
//! shared history. That mirror lives under the client's own work root (in `mirrors/<repo_hash>`),
//! while [`RepoCache`] owns `worktrees/<repo_hash>/<sha>`; the two layouts are disjoint.
//!
//! Do not assume the mirror deduplicates worktrees: the worktree-level deduplication provided
//! here is "one materialized worktree per `(repo, commit)`" plus per-repository fetch
//! serialization. The mirror reduces network/disk churn *across* those per-commit worktrees.
//!
//! # Blocking I/O policy
//!
//! Every recursive or otherwise unbounded filesystem operation (`create_dir_all`,
//! `remove_stale_target`, `rename(2)` and garbage-collection deletes) runs inside
//! [`tokio::task::spawn_blocking`]. Synchronous code in this module only ever performs a
//! single bounded `symlink_metadata`/map operation, and no [`std::sync::MutexGuard`] is
//! ever held across an `.await`.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::Mutex as AsyncMutex;

use super::GitClient;
use super::error::RepoError;
use super::sanitize::{WorktreeLimits, sanitize_worktree};
use super::types::{
    GitSource, RepoCheckout, RepoCredentials, ResolvedRevision, validate_commit_sha,
};

/// Sub-directory of [`RepoCacheConfig::work_root`] that holds materialized worktrees.
const WORKTREE_DIR: &str = "worktrees";

/// Default maximum number of cached worktrees retained before LRU eviction kicks in.
pub const DEFAULT_MAX_ENTRIES: usize = 64;

/// Default maximum idle age of a cached worktree before it becomes eligible for eviction.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(60 * 60);

/// FNV-1a 64-bit offset basis (seed used for the primary hash half).
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Secondary seed used for the second half of the [`repo_hash`] digest.
const SECONDARY_SEED: u64 = 0x9e37_79b9_7f4a_7c15;

/// Monotonic counter making garbage-collection "trash" paths unique.
static TRASH_SEQ: AtomicU64 = AtomicU64::new(0);

/// Configuration for [`RepoCache`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoCacheConfig {
    /// Root directory holding the cache layout (`<work_root>/worktrees/<repo_hash>/<sha>`).
    ///
    /// # Ownership
    ///
    /// **Exactly one [`RepoCache`] instance may own a given `work_root`.** The lease
    /// refcounts live in an in-memory registry, so a second [`RepoCache`] (or a second
    /// process) pointed at the same `work_root` cannot observe the first one's leases and
    /// could garbage-collect a worktree that is still in use. Sharing a `work_root`
    /// between processes is unsupported.
    ///
    /// # Filesystem
    ///
    /// `work_root` MUST live on the same filesystem as the injected [`GitClient`]'s
    /// `work_root`: publishing a checkout is an atomic `rename(2)` from the client's
    /// temporary directory into this cache. A cross-device rename fails with `EXDEV`
    /// (`ErrorKind::CrossesDevices`), which is reported as a terminal
    /// [`RepoError::RepositoryError`] rather than a retryable I/O error.
    pub work_root: PathBuf,
    /// Maximum number of cached worktrees kept after garbage collection.
    /// `0` is valid and evicts everything that is not currently leased.
    pub max_entries: usize,
    /// Maximum **idle** age of a cached worktree before it becomes eligible for eviction.
    ///
    /// The age is measured from the entry's most recent cache hit (`last_used_at`), not
    /// from its creation, so a worktree that keeps being acquired never expires.
    /// [`Duration::ZERO`] therefore evicts every unleased entry on the next pass.
    pub max_age: Duration,
    /// Symlink / resource budgets enforced on every materialized worktree before it is
    /// published into the cache. Defaults to [`WorktreeLimits::default`].
    pub worktree_limits: WorktreeLimits,
}

impl RepoCacheConfig {
    /// Creates a configuration rooted at `work_root` with default bounds
    /// ([`DEFAULT_MAX_ENTRIES`] entries, [`DEFAULT_MAX_AGE`]).
    #[must_use]
    pub fn new(work_root: impl Into<PathBuf>) -> Self {
        Self {
            work_root: work_root.into(),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_age: DEFAULT_MAX_AGE,
            worktree_limits: WorktreeLimits::default(),
        }
    }

    /// Sets the maximum number of retained cached worktrees.
    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Sets the maximum idle age of a cached worktree.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Sets the symlink / resource budgets enforced on every materialized worktree.
    #[must_use]
    pub fn with_worktree_limits(mut self, worktree_limits: WorktreeLimits) -> Self {
        self.worktree_limits = worktree_limits;
        self
    }
}

/// Outcome of a [`RepoCache::collect_garbage`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RepoCacheGcReport {
    /// Number of entries removed from the cache during this pass.
    pub removed_entries: usize,
    /// Number of entries still tracked by the cache when the pass finished.
    pub remaining_entries: usize,
    /// Human-readable descriptions of directory deletions that failed.
    pub failures: Vec<String>,
}

/// Lifecycle of one tracked worktree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    /// The directory is being written — and then verified — by the checkout that reserved this
    /// key.
    ///
    /// Readers treat this as a miss (they wait on the per-repository lock and re-check) so a
    /// half-written or not-yet-sanitized tree is never leased, and garbage collection leaves it
    /// alone. The entry only becomes [`EntryState::Ready`] after
    /// [`sanitize_worktree`] accepted the directory.
    Materializing,
    /// The directory is complete **and verified** and may be handed out as a cache hit.
    Ready,
}

/// One cached, immutable worktree.
#[derive(Debug)]
struct CacheEntry {
    /// Absolute root of the materialized worktree.
    root_dir: PathBuf,
    /// Monotonic creation timestamp, used only to break LRU ties deterministically.
    created_at: Instant,
    /// Monotonic LRU tick of the most recent acquisition.
    last_used: u64,
    /// Timestamp of the most recent acquisition, used for TTL expiry.
    last_used_at: Instant,
    /// Number of live checkout handles (RAII leases) referencing this entry.
    active: Arc<AtomicUsize>,
    /// Whether the directory may be leased yet.
    state: EntryState,
}

/// Shared mutable cache bookkeeping, guarded by a single `std::sync::Mutex`.
#[derive(Debug, Default)]
struct CacheState {
    /// Cached entries keyed by `"{repo_hash}/{commit_sha}"`.
    entries: HashMap<String, CacheEntry>,
    /// Monotonic counter backing LRU ordering.
    tick: u64,
}

/// One directory scheduled for deletion by [`RepoCache::collect_garbage`].
#[derive(Debug)]
struct GcRemoval {
    /// Cache key the directory belonged to.
    key: String,
    /// Absolute path of the directory to delete.
    root_dir: PathBuf,
}

/// RAII lease keeping a cached worktree alive for the lifetime of a [`RepoCheckout`].
///
/// Increments happen under the cache state mutex (so garbage collection cannot remove the
/// entry between the refcount bump and handing the handle to the caller); the decrement
/// happens on drop.
#[derive(Debug)]
struct CheckoutLease {
    active: Arc<AtomicUsize>,
}

impl Drop for CheckoutLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// RAII guard that rolls back a [`CacheEntry`] reservation unless it was published.
///
/// A `checkout` future can be cancelled at any `.await`; without this guard a cancelled
/// materialization would leave a `Materializing` entry holding a phantom lease forever, which
/// garbage collection can never evict. On drop (when not published) the refcount is released
/// and the entry is removed, so the next attempt simply re-materializes and any directory left
/// behind is treated as a stale target.
#[derive(Debug)]
struct ReservationGuard {
    state: Arc<Mutex<CacheState>>,
    key: String,
    active: Arc<AtomicUsize>,
    published: bool,
}

impl ReservationGuard {
    /// The refcount of this reservation (handed to the returned [`CheckoutLease`]).
    fn active(&self) -> &Arc<AtomicUsize> {
        &self.active
    }

    /// Transfers refcount ownership to the lease that is being returned to the caller.
    fn publish(&mut self) {
        self.published = true;
    }
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        if self.published {
            return;
        }
        self.active.fetch_sub(1, Ordering::SeqCst);
        match self.state.lock() {
            Ok(mut state) => {
                let owned = state
                    .entries
                    .get(&self.key)
                    .is_some_and(|entry| Arc::ptr_eq(&entry.active, &self.active));
                if owned {
                    state.entries.remove(&self.key);
                }
            }
            Err(_) => {
                tracing::warn!(
                    key = %self.key,
                    "repo cache state mutex was poisoned while rolling back a reservation"
                );
            }
        }
    }
}

/// Per-repository lock plus commit-keyed immutable worktree cache.
pub struct RepoCache {
    client: Arc<dyn GitClient>,
    config: RepoCacheConfig,
    /// One async mutex per normalized repository URL, serializing fetch/materialize work.
    repo_locks: DashMap<String, Arc<AsyncMutex<()>>>,
    /// Shared cache bookkeeping. `Arc` so blocking tasks can consult the entry table.
    state: Arc<Mutex<CacheState>>,
}

impl fmt::Debug for RepoCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepoCache")
            .field("config", &self.config)
            .field("tracked_repos", &self.repo_locks.len())
            .field(
                "entries",
                &self
                    .state
                    .try_lock()
                    .map(|state| ready_entry_count(&state))
                    .ok(),
            )
            .finish_non_exhaustive()
    }
}

impl RepoCache {
    /// Creates a cache that delegates Git work to `client`.
    #[must_use]
    pub fn new(client: Arc<dyn GitClient>, config: RepoCacheConfig) -> Self {
        Self {
            client,
            config,
            repo_locks: DashMap::new(),
            state: Arc::new(Mutex::new(CacheState::default())),
        }
    }

    /// Returns the active configuration.
    #[must_use]
    pub fn config(&self) -> &RepoCacheConfig {
        &self.config
    }

    /// Resolves `src.target_revision` to a canonical commit SHA (delegated to the client).
    pub async fn resolve_revision(
        &self,
        src: &GitSource,
        creds: &RepoCredentials,
    ) -> Result<ResolvedRevision, RepoError> {
        self.client.resolve_revision(src, creds).await
    }

    /// Returns an immutable worktree for the exact commit `sha`, materializing and caching it
    /// if it is not already present.
    ///
    /// Concurrent calls for the same repository are serialized by a per-repository async mutex
    /// and the cache is re-checked after the lock is acquired, so a commit is materialized at
    /// most once per process even under heavy contention.
    ///
    /// A freshly materialized tree is sanitized with
    /// [`RepoCacheConfig::worktree_limits`] **before** the cache entry becomes visible
    /// (`EntryState::Ready`), so a concurrent caller can never lease an unverified checkout; a
    /// rejected tree is deleted and the terminal error propagated.
    pub async fn checkout(
        &self,
        src: &GitSource,
        sha: &str,
        creds: &RepoCredentials,
    ) -> Result<RepoCheckout, RepoError> {
        validate_commit_sha(sha)?;

        let repo_key = normalize_repo_url(&src.repo_url);
        let repo_hash = repo_hash(&repo_key);

        if let Some(hit) = self.try_cache_hit(&repo_hash, sha)? {
            return Ok(hit);
        }

        let repo_lock = self.repo_lock(&repo_key);
        let guard = repo_lock.lock().await;

        // Double-checked locking: another task may have materialized this commit while we
        // were waiting for the per-repository lock.
        if let Some(hit) = self.try_cache_hit(&repo_hash, sha)? {
            drop(guard);
            return Ok(hit);
        }

        let materialized = self.client.checkout(src, sha, creds).await?;
        if materialized.commit_sha() != sha {
            return Err(RepoError::RepositoryError {
                message: format!(
                    "git client returned a checkout for commit '{}' while '{sha}' was requested",
                    materialized.commit_sha()
                ),
            });
        }

        let cached_root = self.dest_dir(&repo_hash, sha);
        // Reserve the destination *before* touching the filesystem: garbage collection only
        // claims paths whose key is untracked, so a reserved key can never have its directory
        // moved away while the rename below populates it. The guard rolls the reservation back
        // if this future is cancelled or the materialization fails, so a dropped `checkout`
        // future can never leave a permanently un-evictable entry behind.
        let mut reservation = self.reserve_entry(&repo_hash, sha, &cached_root)?;
        let active = Arc::clone(reservation.active());

        let temp_root = materialized.root_dir().to_path_buf();
        let work_root = self.config.work_root.clone();
        let worktree_limits = self.config.worktree_limits;
        let state = Arc::clone(&self.state);
        let repo_hash_owned = repo_hash.clone();
        let sha_owned = sha.to_owned();
        let dest = cached_root.clone();
        let active_for_blocking = Arc::clone(&active);

        // All recursive filesystem work (create_dir_all, stale-target removal, rename), the
        // worktree sanitization and the final publish run on the blocking pool; the client
        // handle is moved in and dropped there because its temporary directory has been
        // renamed away.
        let materialize_result = tokio::task::spawn_blocking(move || {
            let result = materialize(
                &work_root,
                &state,
                &repo_hash_owned,
                &sha_owned,
                &temp_root,
                &dest,
                &active_for_blocking,
            );
            drop(materialized);
            result?;

            // The entry is still `Materializing` here, so the lock-free `try_cache_hit` fast
            // path reports a miss and no caller can lease the tree before it is verified.
            // Only a verified tree may ever become `Ready`.
            //
            // This re-walks a tree that a `gix`-backed client already sanitized in its own
            // `checkout`; the duplicate walk is intentional: the cache cannot know which
            // backend materialized the tree (or whether it sanitized at all), so the cache
            // path is the one place where every materialization is guaranteed to be checked.
            if let Err(err) = sanitize_worktree(&dest, &worktree_limits) {
                // Never publish an unverified tree: remove the just-renamed directory and
                // return the terminal error. The `ReservationGuard` (not yet published) then
                // drops the cache entry, so no entry and no directory are left behind.
                if let Err(cleanup_err) = remove_path(&dest) {
                    tracing::warn!(
                        path = %dest.display(),
                        error = %cleanup_err,
                        "failed to remove rejected checkout directory after sanitization"
                    );
                }
                return Err(err);
            }

            mark_ready(
                &state,
                &entry_key(&repo_hash_owned, &sha_owned),
                &active_for_blocking,
            )
        })
        .await
        .map_err(|join_err| RepoError::RepositoryError {
            message: format!("repo cache materialization task failed: {join_err}"),
        })?;

        materialize_result?;

        drop(guard);
        // From here on the reservation's refcount is owned by the returned lease.
        reservation.publish();

        let checkout =
            RepoCheckout::with_lease(cached_root, sha, Arc::new(CheckoutLease { active }));

        match self.collect_garbage().await {
            Ok(report) => {
                if !report.failures.is_empty() {
                    tracing::warn!(
                        failed_deletions = report.failures.len(),
                        removed_entries = report.removed_entries,
                        remaining_entries = report.remaining_entries,
                        failures = ?report.failures,
                        "repo cache garbage collection removed entries but could not delete \
                         every worktree directory"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "repo cache garbage collection failed");
            }
        }

        Ok(checkout)
    }

    /// Removes idle/expired entries and evicts least-recently-used inactive entries until the
    /// cache is within [`RepoCacheConfig::max_entries`].
    ///
    /// The pass runs in two phases:
    ///
    /// 1. **Plan (synchronous, under the state mutex):** entries are *removed from the map*
    ///    and their `root_dir` paths collected. Once an entry is out of the map no new cache
    ///    hit can acquire it, so evicting it is safe while the deletion is still pending.
    ///    No file is deleted while the mutex is held, and the mutex is never held across an
    ///    `.await`.
    /// 2. **Delete (on the blocking pool):** each collected directory is renamed out of the
    ///    cache namespace and then deleted recursively. The rename is the atomic claim: if a
    ///    concurrent [`Self::checkout`] re-registered the key in the meantime, the entry is
    ///    tracked again and the directory is left untouched.
    ///
    /// Entries with a live checkout handle are never removed, so the cache may temporarily
    /// exceed `max_entries` while those handles are outstanding.
    pub async fn collect_garbage(&self) -> Result<RepoCacheGcReport, RepoError> {
        let mut report = RepoCacheGcReport::default();

        let removals = {
            let mut state = self.state_lock()?;

            let now = Instant::now();
            let max_age = self.config.max_age;
            let expired: Vec<String> = state
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.state == EntryState::Ready
                        && entry.active.load(Ordering::SeqCst) == 0
                        && now.saturating_duration_since(entry.last_used_at) >= max_age
                })
                .map(|(key, _)| key.clone())
                .collect();
            let mut removals = Vec::with_capacity(expired.len());
            for key in expired {
                removals.extend(plan_removal(&mut state, &key, &mut report));
            }

            // `max_entries == 0` means "evict everything that is not leased"; the `None` victim
            // arm breaks the loop instead of spinning when every remaining entry is active.
            loop {
                if ready_entry_count(&state) <= self.config.max_entries {
                    break;
                }
                let victim = state
                    .entries
                    .iter()
                    .filter(|(_, entry)| {
                        entry.state == EntryState::Ready && entry.active.load(Ordering::SeqCst) == 0
                    })
                    .min_by_key(|(_, entry)| (entry.last_used, entry.created_at))
                    .map(|(key, _)| key.clone());
                match victim {
                    Some(key) => removals.extend(plan_removal(&mut state, &key, &mut report)),
                    None => break,
                }
            }

            report.remaining_entries = ready_entry_count(&state);
            removals
        };

        if removals.is_empty() {
            return Ok(report);
        }

        let state = Arc::clone(&self.state);
        report.failures = tokio::task::spawn_blocking(move || delete_removals(&state, removals))
            .await
            .map_err(|join_err| RepoError::RepositoryError {
                message: format!("repo cache garbage collection task failed: {join_err}"),
            })?;

        if !report.failures.is_empty() {
            tracing::warn!(
                failed_deletions = report.failures.len(),
                failures = ?report.failures,
                "repo cache garbage collection failed to delete some worktree directories"
            );
        }

        Ok(report)
    }

    /// Returns the number of tracked cache entries.
    ///
    /// Entries still being materialized by a concurrent [`Self::checkout`] are not counted.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.state.lock() {
            Ok(state) => ready_entry_count(&state),
            Err(_) => {
                tracing::warn!(
                    "repo cache state mutex was poisoned; reporting 0 tracked entries, which may \
                     understate the cache size"
                );
                0
            }
        }
    }

    /// Returns `true` when no cached worktrees are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self.state.lock() {
            Ok(state) => ready_entry_count(&state) == 0,
            Err(_) => {
                tracing::warn!(
                    "repo cache state mutex was poisoned; reporting an empty cache, which may \
                     understate the cache size"
                );
                true
            }
        }
    }

    /// Returns the async mutex guarding all work for `repo_key`, creating it on first use.
    fn repo_lock(&self, repo_key: &str) -> Arc<AsyncMutex<()>> {
        if let Some(existing) = self.repo_locks.get(repo_key) {
            return Arc::clone(existing.value());
        }
        self.repo_locks
            .entry(repo_key.to_owned())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .value()
            .clone()
    }

    /// Returns the shared cache state lock, mapping poisoning to [`RepoError::RepositoryError`].
    fn state_lock(&self) -> Result<MutexGuard<'_, CacheState>, RepoError> {
        lock_state(&self.state)
    }

    /// Absolute destination directory for a materialized commit.
    fn dest_dir(&self, repo_hash: &str, sha: &str) -> PathBuf {
        self.config
            .work_root
            .join(WORKTREE_DIR)
            .join(repo_hash)
            .join(sha)
    }

    /// Registers an in-flight materialization for `(repo_hash, sha)`.
    ///
    /// Called while the per-repository async lock is held, so no other task can be
    /// materializing the same key. Reserving *before* the filesystem work keeps garbage
    /// collection from claiming the destination path mid-materialization, and seeds the
    /// new directory with a lease refcount of 1 from the very first instant.
    ///
    /// A leftover reservation can only exist when a previous materialization was cancelled
    /// while awaiting the blocking task, so overwriting it is the recovery path.
    fn reserve_entry(
        &self,
        repo_hash: &str,
        sha: &str,
        dest: &Path,
    ) -> Result<ReservationGuard, RepoError> {
        let mut state = self.state_lock()?;
        let now = Instant::now();
        state.tick += 1;
        let tick = state.tick;
        let key = entry_key(repo_hash, sha);
        let active = Arc::new(AtomicUsize::new(1));
        state.entries.insert(
            key.clone(),
            CacheEntry {
                root_dir: dest.to_path_buf(),
                created_at: now,
                last_used: tick,
                last_used_at: now,
                active: Arc::clone(&active),
                state: EntryState::Materializing,
            },
        );
        Ok(ReservationGuard {
            state: Arc::clone(&self.state),
            key,
            active,
            published: false,
        })
    }

    /// Looks up a cached worktree and bumps its refcount + LRU/TTL bookkeeping on success.
    ///
    /// Both mutations happen while the state mutex is held, so a concurrent
    /// [`Self::collect_garbage`] can never delete the directory after we returned it.
    fn try_cache_hit(&self, repo_hash: &str, sha: &str) -> Result<Option<RepoCheckout>, RepoError> {
        let key = entry_key(repo_hash, sha);
        let mut state = self.state_lock()?;

        let Some((root_dir, entry_state, active_now)) = state.entries.get(&key).map(|entry| {
            (
                entry.root_dir.clone(),
                entry.state,
                entry.active.load(Ordering::SeqCst),
            )
        }) else {
            return Ok(None);
        };

        if entry_state != EntryState::Ready {
            // A concurrent checkout for this repository is publishing the directory. Report a
            // miss (never a lease, never a removal) so the caller waits on the per-repository
            // lock and re-checks.
            return Ok(None);
        }

        // `is_dir()` collapses "missing" and "unreachable" (`EACCES`, `EIO`, ...) into `false`,
        // which used to delete live worktrees. `symlink_metadata` lets us tell them apart and
        // never follows a symlink planted at the cache path.
        let metadata = match std::fs::symlink_metadata(&root_dir) {
            Ok(metadata) => Some(metadata),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(RepoError::Io {
                    context: format!("inspecting cached worktree '{}'", root_dir.display()),
                    source,
                });
            }
        };

        let directory_present = metadata.as_ref().is_some_and(std::fs::Metadata::is_dir);
        if !directory_present {
            if active_now > 0 {
                // Someone still holds a lease: never fabricate a hit and never drop the entry
                // (dropping it would let a re-materialization delete a live consumer's tree).
                return Err(RepoError::RepositoryError {
                    message: format!(
                        "cached worktree for {sha} disappeared while still leased \
                         ({active_now} active leases) at '{}'",
                        root_dir.display()
                    ),
                });
            }
            // Unleased and genuinely gone (crash cleanup, manual removal): forget the stale
            // entry and fall through to a fresh materialization.
            state.entries.remove(&key);
            return Ok(None);
        }

        state.tick += 1;
        let tick = state.tick;
        let now = Instant::now();
        let Some(entry) = state.entries.get_mut(&key) else {
            return Ok(None);
        };
        entry.last_used = tick;
        entry.last_used_at = now;
        entry.active.fetch_add(1, Ordering::SeqCst);
        let active = Arc::clone(&entry.active);
        drop(state);

        Ok(Some(RepoCheckout::with_lease(
            root_dir,
            sha,
            Arc::new(CheckoutLease { active }),
        )))
    }
}

/// Returns how many entries are fully materialized (and therefore leasable).
fn ready_entry_count(state: &CacheState) -> usize {
    state
        .entries
        .values()
        .filter(|entry| entry.state == EntryState::Ready)
        .count()
}

/// Locks the cache state, mapping poisoning to a terminal [`RepoError`].
fn lock_state(state: &Mutex<CacheState>) -> Result<MutexGuard<'_, CacheState>, RepoError> {
    state.lock().map_err(|_| RepoError::RepositoryError {
        message: "repo cache state mutex was poisoned".to_owned(),
    })
}

/// Garbage-collection plan step: drop `key` from the map and report its directory.
///
/// Only map bookkeeping happens here; the caller deletes the directory on the blocking pool.
fn plan_removal(
    state: &mut CacheState,
    key: &str,
    report: &mut RepoCacheGcReport,
) -> Option<GcRemoval> {
    let entry = state.entries.remove(key)?;
    report.removed_entries += 1;
    Some(GcRemoval {
        key: key.to_owned(),
        root_dir: entry.root_dir,
    })
}

/// Garbage-collection delete phase, executed on the blocking pool.
///
/// Every doomed directory is first renamed out of the cache namespace (under a short state
/// lock) so the recursive delete can never race with a concurrent materialization that
/// re-creates the same path.
fn delete_removals(state: &Mutex<CacheState>, removals: Vec<GcRemoval>) -> Vec<String> {
    let mut failures = Vec::new();
    for removal in removals {
        match claim_for_deletion(state, &removal.key, &removal.root_dir) {
            Ok(Some(trash)) => {
                if let Err(err) = remove_path(&trash) {
                    failures.push(format!(
                        "failed to remove cached worktree '{}': {err}",
                        removal.root_dir.display()
                    ));
                }
            }
            Ok(None) => {}
            Err(err) => failures.push(format!(
                "failed to remove cached worktree '{}': {err}",
                removal.root_dir.display()
            )),
        }
    }
    failures
}

/// Atomically claims a doomed cache directory for deletion.
///
/// Returns `Ok(Some(trash_path))` once the directory has been renamed out of the cache
/// namespace, `Ok(None)` when there is nothing (left) to delete, and `Err` on I/O failure.
/// A key that was re-registered after the plan phase is never touched.
fn claim_for_deletion(
    state: &Mutex<CacheState>,
    key: &str,
    path: &Path,
) -> Result<Option<PathBuf>, RepoError> {
    let guard = lock_state(state)?;
    if guard.entries.contains_key(key) {
        tracing::debug!(
            key = key,
            path = %path.display(),
            "skipping cache directory deletion; the entry was re-registered"
        );
        return Ok(None);
    }
    let trash = trash_path(path);
    match std::fs::rename(path, &trash) {
        Ok(()) => Ok(Some(trash)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(RepoError::Io {
            context: format!("claiming cached worktree '{}' for deletion", path.display()),
            source,
        }),
    }
}

/// Builds a unique sibling path used to quarantine a directory that is being deleted.
fn trash_path(path: &Path) -> PathBuf {
    let seq = TRASH_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.trash-{}-{seq}", std::process::id()))
}

/// Recursively deletes a path without following symlinks.
fn remove_path(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Publishes a client-materialized worktree into its final cache location (blocking).
///
/// Returns as soon as the tree has been renamed into place. The cache entry deliberately stays
/// [`EntryState::Materializing`]: the caller must sanitize the destination and only then call
/// [`mark_ready`], so no [`EntryState::Ready`] entry can exist before verification.
fn materialize(
    work_root: &Path,
    state: &Mutex<CacheState>,
    repo_hash: &str,
    sha: &str,
    temp_root: &Path,
    dest: &Path,
    active: &Arc<AtomicUsize>,
) -> Result<(), RepoError> {
    let repo_dir = work_root.join(WORKTREE_DIR).join(repo_hash);
    std::fs::create_dir_all(&repo_dir).map_err(|source| RepoError::Io {
        context: format!("creating repo cache directory '{}'", repo_dir.display()),
        source,
    })?;

    let key = entry_key(repo_hash, sha);
    remove_stale_target(state, &key, dest, active)?;

    match std::fs::rename(temp_root, dest) {
        Ok(()) => {}
        Err(source) if source.kind() == std::io::ErrorKind::CrossesDevices => {
            // Retrying can never help: the two work roots live on different mounts.
            return Err(RepoError::RepositoryError {
                message: format!(
                    "cannot publish checkout '{}' into cache '{}': \
                     RepoCacheConfig::work_root and the GitClient work_root must share a \
                     filesystem so the worktree can be moved atomically ({source})",
                    temp_root.display(),
                    dest.display()
                ),
            });
        }
        Err(source) => {
            return Err(RepoError::Io {
                context: format!(
                    "moving checkout '{}' into cache '{}'",
                    temp_root.display(),
                    dest.display()
                ),
                source,
            });
        }
    }

    // Deliberately *not* marked ready: the caller sanitizes `dest` first and only then calls
    // `mark_ready`, so the entry stays unleased (`Materializing`) until it is verified.
    Ok(())
}

/// Marks a reservation as fully materialized and verified.
///
/// This is the only place an entry may become [`EntryState::Ready`]; it must be called after
/// [`sanitize_worktree`] accepted the directory, never before.
fn mark_ready(
    state: &Mutex<CacheState>,
    key: &str,
    active: &Arc<AtomicUsize>,
) -> Result<(), RepoError> {
    let mut guard = lock_state(state)?;
    if let Some(entry) = guard.entries.get_mut(key)
        && Arc::ptr_eq(&entry.active, active)
    {
        entry.state = EntryState::Ready;
    }
    Ok(())
}

/// Removes a leftover cache target created by a crashed earlier process.
///
/// The in-memory entry table is consulted first: deleting the destination of a *tracked*
/// entry would destroy a live worktree, so a tracked key is refused outright.
///
/// The one exception is the reservation this very call owns — the `Materializing` entry whose
/// refcount `Arc` is pointer-equal to `active`. That reservation is not a live worktree (its
/// directory is what we are about to create), and it exists precisely so garbage collection
/// cannot claim the path mid-materialization; refusing to clear a stale leftover underneath it
/// would make recovery from a crashed peer impossible. Every other tracked key — `Ready`
/// entries, or `Materializing` entries owned by someone else — is an error. That case is
/// unreachable today (the caller holds the per-repository lock), but the check stays defensive
/// so a second cache instance or a future caller can never delete a live tree.
fn remove_stale_target(
    state: &Mutex<CacheState>,
    key: &str,
    dest: &Path,
    active: &Arc<AtomicUsize>,
) -> Result<(), RepoError> {
    {
        let guard = lock_state(state)?;
        if let Some(entry) = guard.entries.get(key)
            && (entry.state == EntryState::Ready || !Arc::ptr_eq(&entry.active, active))
        {
            return Err(RepoError::RepositoryError {
                message: format!(
                    "refusing to delete cached worktree '{}' for tracked cache entry '{key}'",
                    dest.display()
                ),
            });
        }
    }

    let metadata = match std::fs::symlink_metadata(dest) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(RepoError::Io {
                context: format!("inspecting cache path '{}'", dest.display()),
                source,
            });
        }
    };

    let removal = if metadata.is_dir() {
        std::fs::remove_dir_all(dest)
    } else {
        std::fs::remove_file(dest)
    };
    removal.map_err(|source| RepoError::Io {
        context: format!("removing stale cache path '{}'", dest.display()),
        source,
    })
}

/// Cache key for one materialized commit.
fn entry_key(repo_hash: &str, sha: &str) -> String {
    format!("{repo_hash}/{sha}")
}

/// Normalizes a repository URL into a conservative cache key.
///
/// Only whitespace and redundant trailing separators are removed: rewriting anything else
/// (case, `.git` suffix, percent-encoding) risks collapsing two distinct repositories onto
/// the same lock and directory, which is far worse than missing a cache hit.
pub(crate) fn normalize_repo_url(repo_url: &str) -> String {
    let trimmed = repo_url.trim();
    let stripped = trimmed.trim_end_matches('/');
    if stripped.is_empty() {
        trimmed.to_owned()
    } else {
        stripped.to_owned()
    }
}

/// Derives a stable, filesystem-safe 32-character lowercase hex digest for a repository URL.
///
/// Implemented with FNV-1a 64 over two independent seeds so no additional hashing crate is
/// required. The output contains only `[0-9a-f]`, so it can never introduce `..` or absolute
/// path components into the cache layout.
pub(crate) fn repo_hash(normalized_url: &str) -> String {
    let bytes = normalized_url.as_bytes();
    format!(
        "{:016x}{:016x}",
        fnv1a64(FNV_OFFSET_BASIS, bytes),
        fnv1a64(SECONDARY_SEED, bytes)
    )
}

fn fnv1a64(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::process::Command;
    use std::sync::atomic::AtomicBool;

    use tempfile::TempDir;
    use tokio::task::JoinSet;

    use super::*;
    use crate::repo::{GixGitClient, GixGitClientConfig, RepoUrlPolicy};

    const TEST_MAX_AGE: Duration = Duration::from_secs(60 * 60);

    struct Fixture {
        _root: TempDir,
        bare_path: PathBuf,
        c1: String,
        c2: String,
        c3: String,
    }

    /// [`GitClient`] decorator counting delegated calls so tests can prove cache hits.
    struct CountingClient {
        inner: GixGitClient,
        checkouts: AtomicUsize,
        resolves: AtomicUsize,
    }

    impl CountingClient {
        fn checkout_count(&self) -> usize {
            self.checkouts.load(Ordering::SeqCst)
        }
    }

    impl GitClient for CountingClient {
        fn resolve_revision<'a>(
            &'a self,
            src: &'a GitSource,
            creds: &'a RepoCredentials,
        ) -> crate::repo::RepoFuture<'a, ResolvedRevision> {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            self.inner.resolve_revision(src, creds)
        }

        fn checkout<'a>(
            &'a self,
            src: &'a GitSource,
            sha: &'a str,
            creds: &'a RepoCredentials,
        ) -> crate::repo::RepoFuture<'a, RepoCheckout> {
            self.checkouts.fetch_add(1, Ordering::SeqCst);
            self.inner.checkout(src, sha, creds)
        }
    }

    /// Deterministic, git-free [`GitClient`] used by the GC/acquire stress test.
    ///
    /// Each checkout writes a complete worktree into a fresh temporary directory **under**
    /// `work_root` (same filesystem, so the cache publish is an atomic rename) and returns a
    /// handle for it. Content is derived from the SHA, so a torn or recycled directory is
    /// detectable byte-for-byte.
    struct StubClient {
        work_root: PathBuf,
        /// Extra regular files written next to the standard fixture files, so tests can push a
        /// benign tree past a configured `WorktreeLimits::max_files`.
        extra_files: usize,
        checkouts: AtomicUsize,
        seq: AtomicUsize,
    }

    impl StubClient {
        fn new(work_root: PathBuf) -> Self {
            Self {
                work_root,
                extra_files: 0,
                checkouts: AtomicUsize::new(0),
                seq: AtomicUsize::new(0),
            }
        }

        fn with_extra_files(work_root: PathBuf, extra_files: usize) -> Self {
            Self {
                extra_files,
                ..Self::new(work_root)
            }
        }
    }

    /// Expected `README.md` body for a stub commit.
    fn stub_readme(sha: &str) -> String {
        let mut body = format!("sha={sha}\n");
        for line in 0..64 {
            body.push_str(&format!("line-{line:03}: payload for {sha}\n"));
        }
        body
    }

    /// Expected `apps/base/deployment.yaml` body for a stub commit.
    fn stub_deployment(sha: &str) -> String {
        format!("kind: Deployment\ncommit: {sha}\n")
    }

    fn stub_io(context: &str) -> impl Fn(std::io::Error) -> RepoError + '_ {
        move |source| RepoError::Io {
            context: context.to_owned(),
            source,
        }
    }

    impl GitClient for StubClient {
        fn resolve_revision<'a>(
            &'a self,
            _src: &'a GitSource,
            _creds: &'a RepoCredentials,
        ) -> crate::repo::RepoFuture<'a, ResolvedRevision> {
            Box::pin(async move {
                Err(RepoError::RepositoryError {
                    message: "stub client does not resolve revisions".to_owned(),
                })
            })
        }

        fn checkout<'a>(
            &'a self,
            _src: &'a GitSource,
            sha: &'a str,
            _creds: &'a RepoCredentials,
        ) -> crate::repo::RepoFuture<'a, RepoCheckout> {
            self.checkouts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                validate_commit_sha(sha)?;
                let work_root = self.work_root.clone();
                let seq = self.seq.fetch_add(1, Ordering::SeqCst);
                let sha_owned = sha.to_owned();
                let readme = stub_readme(sha);
                let deployment = stub_deployment(sha);
                let extra_files = self.extra_files;
                tokio::task::spawn_blocking(move || {
                    std::fs::create_dir_all(&work_root)
                        .map_err(stub_io("creating stub work_root"))?;
                    let temp =
                        work_root.join(format!("ferriscd-stub-{}-{seq}", std::process::id()));
                    std::fs::create_dir_all(temp.join("apps/base"))
                        .map_err(stub_io("creating stub worktree"))?;
                    std::fs::write(temp.join("README.md"), readme)
                        .map_err(stub_io("writing stub README.md"))?;
                    std::fs::write(temp.join("apps/base/deployment.yaml"), deployment)
                        .map_err(stub_io("writing stub deployment.yaml"))?;
                    for index in 0..extra_files {
                        std::fs::write(temp.join(format!("extra-{index}.txt")), "x")
                            .map_err(stub_io("writing stub extra file"))?;
                    }
                    Ok(RepoCheckout::new(temp, sha_owned))
                })
                .await
                .map_err(|join_err| RepoError::RepositoryError {
                    message: format!("stub checkout task failed: {join_err}"),
                })?
            })
        }
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

    /// Builds a bare repository whose three commits each rewrite `README.md` and add a file.
    fn build_fixture() -> Fixture {
        let root = tempfile::tempdir().expect("create fixture temp dir");
        let work = root.path().join("work");
        let bare = root.path().join("remote.git");
        std::fs::create_dir_all(&work).expect("create work dir");
        git_cmd(&work, &["init", "--initial-branch=main"]);

        std::fs::create_dir_all(work.join("apps/base")).expect("mkdir apps/base");
        std::fs::write(work.join("README.md"), "version=c1\n").expect("write README c1");
        std::fs::write(
            work.join("apps/base/deployment.yaml"),
            "kind: Deployment\nmetadata:\n  name: app\n",
        )
        .expect("write deployment");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "commit c1"]);
        let c1 = git_cmd(&work, &["rev-parse", "HEAD"]);

        std::fs::write(work.join("README.md"), "version=c2\n").expect("write README c2");
        std::fs::write(work.join("SECOND.md"), "second commit only\n").expect("write SECOND");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "commit c2"]);
        let c2 = git_cmd(&work, &["rev-parse", "HEAD"]);

        std::fs::write(work.join("README.md"), "version=c3\n").expect("write README c3");
        std::fs::write(work.join("THIRD.md"), "third commit only\n").expect("write THIRD");
        git_cmd(&work, &["add", "."]);
        git_cmd(&work, &["commit", "-m", "commit c3"]);
        let c3 = git_cmd(&work, &["rev-parse", "HEAD"]);

        git_cmd(
            root.path(),
            &[
                "clone",
                "--bare",
                work.to_str().expect("utf8 path"),
                bare.to_str().expect("utf8 path"),
            ],
        );
        git_cmd(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);

        Fixture {
            _root: root,
            bare_path: bare,
            c1,
            c2,
            c3,
        }
    }

    /// Builds a cache whose client writes temporary worktrees into the cache root, so the
    /// final move is a same-filesystem atomic rename.
    fn build_cache(
        work_root: &Path,
        max_entries: usize,
        max_age: Duration,
    ) -> (Arc<CountingClient>, RepoCache) {
        let client = Arc::new(CountingClient {
            inner: GixGitClient::new(
                GixGitClientConfig::new()
                    .with_url_policy(RepoUrlPolicy::AllowLocal)
                    .with_work_root(work_root.to_path_buf()),
            ),
            checkouts: AtomicUsize::new(0),
            resolves: AtomicUsize::new(0),
        });
        let config = RepoCacheConfig::new(work_root)
            .with_max_entries(max_entries)
            .with_max_age(max_age);
        let cache = RepoCache::new(Arc::clone(&client) as Arc<dyn GitClient>, config);
        (client, cache)
    }

    fn read_file(root: &Path, name: &str) -> String {
        std::fs::read_to_string(root.join(name))
            .unwrap_or_else(|err| panic!("reading {name} under {}: {err}", root.display()))
    }

    fn source(fx: &Fixture) -> GitSource {
        GitSource::new(fx.bare_path.to_str().expect("utf8 path"), "main", "")
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
    async fn repeat_checkout_of_same_commit_is_a_cache_hit() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (client, cache) = build_cache(work_root.path(), 8, TEST_MAX_AGE);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let first = cache
            .checkout(&src, &fx.c2, &creds)
            .await
            .expect("first checkout");
        let first_root = first.root_dir().to_path_buf();
        assert_eq!(
            first_root,
            work_root
                .path()
                .join("worktrees")
                .join(repo_hash(&normalize_repo_url(&src.repo_url)))
                .join(&fx.c2)
        );
        assert_eq!(first.commit_sha(), fx.c2);
        assert_eq!(read_file(first.root_dir(), "README.md"), "version=c2\n");
        assert!(first.root_dir().join("SECOND.md").is_file());
        assert!(!first.root_dir().join("THIRD.md").exists());
        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());
        drop(first);

        let second = cache
            .checkout(&src, &fx.c2, &creds)
            .await
            .expect("second checkout");
        assert_eq!(second.root_dir(), first_root);
        assert_eq!(read_file(second.root_dir(), "README.md"), "version=c2\n");
        assert_eq!(cache.len(), 1);
        assert_eq!(
            client.checkout_count(),
            1,
            "repeat checkout of the same commit must be served from the cache"
        );

        // The handle keeps the worktree alive; dropping it must NOT delete a cached entry.
        drop(second);
        assert!(first_root.is_dir(), "cache entry must survive handle drop");
    }

    #[tokio::test]
    async fn distinct_commits_get_distinct_cached_worktrees() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (client, cache) = build_cache(work_root.path(), 8, TEST_MAX_AGE);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let c1 = cache.checkout(&src, &fx.c1, &creds).await.expect("c1");
        let c2 = cache.checkout(&src, &fx.c2, &creds).await.expect("c2");
        let c3 = cache.checkout(&src, &fx.c3, &creds).await.expect("c3");

        assert_ne!(c1.root_dir(), c2.root_dir());
        assert_ne!(c2.root_dir(), c3.root_dir());
        assert_ne!(c1.root_dir(), c3.root_dir());

        assert_eq!(read_file(c1.root_dir(), "README.md"), "version=c1\n");
        assert_eq!(read_file(c2.root_dir(), "README.md"), "version=c2\n");
        assert_eq!(read_file(c3.root_dir(), "README.md"), "version=c3\n");
        assert!(!c1.root_dir().join("SECOND.md").exists());
        assert!(c2.root_dir().join("SECOND.md").is_file());
        assert!(!c2.root_dir().join("THIRD.md").exists());
        assert!(c3.root_dir().join("THIRD.md").is_file());

        assert_eq!(cache.len(), 3);
        assert_eq!(client.checkout_count(), 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn sixteen_concurrent_checkouts_across_three_commits_are_corruption_free() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (client, cache) = build_cache(work_root.path(), 64, TEST_MAX_AGE);
        let cache = Arc::new(cache);
        let src = Arc::new(source(&fx));

        let commits: Vec<(String, &'static str)> = vec![
            (fx.c1.clone(), "version=c1\n"),
            (fx.c2.clone(), "version=c2\n"),
            (fx.c3.clone(), "version=c3\n"),
        ];

        let mut tasks = Vec::with_capacity(16);
        for index in 0..16usize {
            let cache = Arc::clone(&cache);
            let src = Arc::clone(&src);
            let (sha, expected) = commits[index % commits.len()].clone();
            tasks.push(tokio::spawn(async move {
                let checkout = cache
                    .checkout(&src, &sha, &RepoCredentials::Anonymous)
                    .await
                    .unwrap_or_else(|err| panic!("concurrent checkout of {sha} failed: {err}"));
                assert_eq!(checkout.commit_sha(), sha);
                // Read every file while the lease is still held: a torn checkout would surface
                // as missing or partial content here.
                let tree = snapshot_tree(checkout.root_dir());
                (sha, expected, checkout.root_dir().to_path_buf(), tree)
            }));
        }

        let mut root_by_sha: BTreeMap<String, PathBuf> = BTreeMap::new();
        for task in tasks {
            let (sha, expected, root, tree) = task.await.expect("task must not panic");
            assert_eq!(
                tree.get("README.md").map(String::as_str),
                Some(expected),
                "corrupt README for commit {sha} at {}",
                root.display()
            );
            assert!(
                tree.contains_key("apps/base/deployment.yaml"),
                "missing apps/base/deployment.yaml for commit {sha} at {}",
                root.display()
            );
            assert_eq!(
                tree.contains_key("SECOND.md"),
                expected != "version=c1\n",
                "unexpected SECOND.md presence for commit {sha} at {}",
                root.display()
            );
            match root_by_sha.get(&sha) {
                Some(existing) => assert_eq!(existing, &root, "commit {sha} mapped to two roots"),
                None => {
                    root_by_sha.insert(sha, root);
                }
            }
        }

        assert_eq!(
            root_by_sha.len(),
            3,
            "each commit must map to one cached root"
        );
        assert_eq!(cache.len(), 3);
        assert_eq!(
            client.checkout_count(),
            3,
            "per-repo lock + double-checked cache must materialize each commit exactly once"
        );
    }

    #[tokio::test]
    async fn size_bound_gc_never_evicts_active_entries() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (_client, cache) = build_cache(work_root.path(), 1, TEST_MAX_AGE);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let held = cache.checkout(&src, &fx.c1, &creds).await.expect("c1");
        let held_root = held.root_dir().to_path_buf();
        let other = cache.checkout(&src, &fx.c2, &creds).await.expect("c2");
        let other_root = other.root_dir().to_path_buf();

        // The bound is temporarily exceeded because both entries are leased.
        assert_eq!(cache.len(), 2);
        assert!(held_root.is_dir());
        assert!(other_root.is_dir());

        drop(held);
        let report = cache.collect_garbage().await.expect("gc");

        assert_eq!(report.removed_entries, 1);
        assert_eq!(report.remaining_entries, 1);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(!held_root.exists(), "inactive entry directory must be gone");
        assert!(other_root.is_dir(), "active entry directory must survive");
        assert_eq!(read_file(other.root_dir(), "README.md"), "version=c2\n");
        assert_eq!(cache.len(), 1);

        let report = cache.collect_garbage().await.expect("gc again");
        assert_eq!(report.removed_entries, 0, "nothing inactive may be evicted");
        assert_eq!(report.remaining_entries, 1);
        drop(other);
    }

    #[tokio::test]
    async fn ttl_gc_respects_active_leases() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (_client, cache) = build_cache(work_root.path(), 8, Duration::ZERO);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let held = cache.checkout(&src, &fx.c1, &creds).await.expect("c1");
        let held_root = held.root_dir().to_path_buf();
        assert!(held_root.is_dir());

        // Expired by TTL, but still leased: must not be collected.
        let report = cache.collect_garbage().await.expect("gc while active");
        assert_eq!(report.removed_entries, 0);
        assert_eq!(report.remaining_entries, 1);
        assert!(held_root.is_dir());
        assert_eq!(read_file(held.root_dir(), "README.md"), "version=c1\n");

        drop(held);
        let report = cache.collect_garbage().await.expect("gc after drop");
        assert_eq!(report.removed_entries, 1);
        assert_eq!(report.remaining_entries, 0);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(!held_root.exists(), "expired entry directory must be gone");
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn gc_removes_directories_and_reports_remaining_entries() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (_client, cache) = build_cache(work_root.path(), 0, TEST_MAX_AGE);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let first = cache.checkout(&src, &fx.c1, &creds).await.expect("c1");
        let first_root = first.root_dir().to_path_buf();
        let second = cache.checkout(&src, &fx.c2, &creds).await.expect("c2");
        let second_root = second.root_dir().to_path_buf();
        assert_eq!(cache.len(), 2);
        assert!(first_root.is_dir() && second_root.is_dir());

        // max_entries = 0 with every entry leased: report success instead of spinning.
        let report = cache
            .collect_garbage()
            .await
            .expect("gc with all entries active");
        assert_eq!(report.removed_entries, 0);
        assert_eq!(report.remaining_entries, 2);

        drop(first);
        drop(second);
        let report = cache.collect_garbage().await.expect("gc after drops");
        assert_eq!(report.removed_entries, 2);
        assert_eq!(report.remaining_entries, 0);
        assert!(!first_root.exists());
        assert!(!second_root.exists());
    }

    /// TTL is measured from the *last use*, so a repeatedly acquired entry keeps its lease on
    /// life and is never mistaken for a vanished directory.
    #[tokio::test]
    async fn ttl_expires_on_last_use_not_creation() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (_client, cache) = build_cache(work_root.path(), 8, Duration::ZERO);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let held = cache.checkout(&src, &fx.c1, &creds).await.expect("c1");
        let root = held.root_dir().to_path_buf();
        drop(held);

        // Re-acquire several times: each hit refreshes `last_used_at`.
        for _ in 0..3 {
            let hit = cache.checkout(&src, &fx.c1, &creds).await.expect("hit");
            assert_eq!(hit.root_dir(), root);
            assert_eq!(read_file(hit.root_dir(), "README.md"), "version=c1\n");
        }

        // With `max_age == ZERO` every unleased entry is idle, so the refreshed entry is still
        // collected — the point is that the repeated hits never degraded into a re-materialize.
        let report = cache.collect_garbage().await.expect("gc");
        assert_eq!(report.removed_entries, 1);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
    }

    /// A junk tree left at a previously garbage-collected cache path must never be served.
    #[tokio::test]
    async fn stale_destination_is_replaced_on_rematerialization() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (client, cache) = build_cache(work_root.path(), 8, Duration::ZERO);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let first = cache.checkout(&src, &fx.c2, &creds).await.expect("first");
        let root = first.root_dir().to_path_buf();
        drop(first);

        let report = cache.collect_garbage().await.expect("gc with zero max_age");
        assert_eq!(report.removed_entries, 1);
        assert_eq!(report.remaining_entries, 0);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(!root.exists(), "collected directory must be gone");

        // Recreate the exact cache path with unrelated junk (simulates a crashed peer or a
        // stale on-disk leftover from an earlier run).
        std::fs::create_dir_all(root.join("nested")).expect("create junk dir");
        std::fs::write(root.join("README.md"), "junk\n").expect("write junk README");
        std::fs::write(root.join("nested/junk.txt"), "junk\n").expect("write junk file");

        let second = cache.checkout(&src, &fx.c2, &creds).await.expect("second");
        assert_eq!(second.root_dir(), root.as_path());
        assert_eq!(read_file(second.root_dir(), "README.md"), "version=c2\n");
        assert!(
            second.root_dir().join("SECOND.md").is_file(),
            "expected commit content must be materialized"
        );
        assert!(
            !second.root_dir().join("nested").exists(),
            "stale destination content must have been replaced"
        );
        assert_eq!(client.checkout_count(), 2);
        assert_eq!(cache.len(), 1);
    }

    /// An unleased entry whose directory vanished behind our back self-heals.
    #[tokio::test]
    async fn vanished_cached_directory_self_heals() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (client, cache) = build_cache(work_root.path(), 8, TEST_MAX_AGE);
        let src = source(&fx);
        let creds = RepoCredentials::Anonymous;

        let first = cache.checkout(&src, &fx.c3, &creds).await.expect("first");
        let root = first.root_dir().to_path_buf();
        drop(first);

        std::fs::remove_dir_all(&root).expect("remove cached directory behind the cache's back");
        assert!(!root.exists());

        let second = cache
            .checkout(&src, &fx.c3, &creds)
            .await
            .expect("self-healing checkout");
        assert_eq!(second.root_dir(), root.as_path());
        assert_eq!(read_file(second.root_dir(), "README.md"), "version=c3\n");
        assert!(second.root_dir().join("THIRD.md").is_file());
        assert_eq!(cache.len(), 1);
        assert_eq!(
            client.checkout_count(),
            2,
            "a vanished unleased directory must be re-materialized"
        );
    }

    /// Losing the directory of a *leased* entry must fail terminally, never silently.
    #[tokio::test]
    async fn vanished_directory_of_active_lease_is_a_terminal_error() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (client, cache) = build_cache(work_root.path(), 8, TEST_MAX_AGE);
        let cache = Arc::new(cache);
        let src = Arc::new(source(&fx));
        let creds = RepoCredentials::Anonymous;

        let held = cache
            .checkout(&src, &fx.c2, &creds)
            .await
            .expect("held checkout");
        let root = held.root_dir().to_path_buf();
        std::fs::remove_dir_all(&root).expect("remove live leased directory");

        let err = {
            let cache = Arc::clone(&cache);
            let src = Arc::clone(&src);
            let sha = fx.c2.clone();
            tokio::spawn(async move { cache.checkout(&src, &sha, &creds).await })
                .await
                .expect("probe task must not panic")
                .expect_err("a live lease whose directory vanished must not be re-materialized")
        };

        match &err {
            RepoError::RepositoryError { message } => {
                assert!(
                    message.contains("disappeared while still leased"),
                    "unexpected message: {message}"
                );
                assert!(
                    message.contains(&fx.c2),
                    "message must name the commit: {message}"
                );
            }
            other => panic!("expected a terminal RepositoryError, got {other:?}"),
        }
        assert!(!err.is_retryable(), "the failure must be terminal");
        assert_eq!(
            client.checkout_count(),
            1,
            "the cache must not silently re-materialize over a live lease"
        );
        assert_eq!(
            cache.len(),
            1,
            "the entry must stay tracked while a lease is outstanding"
        );

        // The live handle is still returned to its owner, untouched.
        assert_eq!(held.commit_sha(), fx.c2);
    }

    /// Proves the lease refcount (Trap Guard) under concurrent acquisition + GC pressure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_gc_never_deletes_a_live_worktree() {
        let work_root = tempfile::tempdir().expect("create cache work root");
        let client = Arc::new(StubClient::new(work_root.path().to_path_buf()));
        let cache = Arc::new(RepoCache::new(
            Arc::clone(&client) as Arc<dyn GitClient>,
            RepoCacheConfig::new(work_root.path())
                .with_max_entries(0)
                .with_max_age(Duration::ZERO),
        ));
        let src = Arc::new(GitSource::new(
            "https://example.test/ferris-cd/stub.git",
            "main",
            "apps",
        ));
        let shas: Vec<String> = (1..=3u64).map(|value| format!("{value:040x}")).collect();

        const WORKERS: usize = 8;
        const ITERATIONS: usize = 16;

        let mut workers = JoinSet::new();
        for worker in 0..WORKERS {
            let cache = Arc::clone(&cache);
            let src = Arc::clone(&src);
            let shas = shas.clone();
            workers.spawn(async move {
                for iteration in 0..ITERATIONS {
                    let sha = shas[(worker + iteration) % shas.len()].clone();
                    let expected_readme = stub_readme(&sha);
                    let expected_deployment = stub_deployment(&sha);
                    let checkout = cache
                        .checkout(&src, &sha, &RepoCredentials::Anonymous)
                        .await
                        .unwrap_or_else(|err| panic!("checkout of {sha} under gc pressure: {err}"));
                    assert_eq!(checkout.commit_sha(), sha);
                    // Read the full file while the lease is held: a directory reclaimed by GC
                    // would surface as a missing file or truncated content here.
                    let readme = std::fs::read_to_string(checkout.root_dir().join("README.md"))
                        .unwrap_or_else(|err| {
                            panic!(
                                "reading README.md of {sha} at {}: {err}",
                                checkout.root_dir().display()
                            )
                        });
                    assert_eq!(
                        readme,
                        expected_readme,
                        "torn worktree for {sha} at {}",
                        checkout.root_dir().display()
                    );
                    let deployment = std::fs::read_to_string(
                        checkout.root_dir().join("apps/base/deployment.yaml"),
                    )
                    .unwrap_or_else(|err| {
                        panic!(
                            "reading deployment.yaml of {sha} at {}: {err}",
                            checkout.root_dir().display()
                        )
                    });
                    assert_eq!(deployment, expected_deployment);
                    drop(checkout);
                    tokio::task::yield_now().await;
                }
            });
        }

        let done = Arc::new(AtomicBool::new(false));
        let collector = {
            let cache = Arc::clone(&cache);
            let done = Arc::clone(&done);
            tokio::spawn(async move {
                let mut passes = 0usize;
                while !done.load(Ordering::SeqCst) {
                    let report = cache
                        .collect_garbage()
                        .await
                        .expect("gc under acquisition pressure must not fail");
                    assert!(
                        report.remaining_entries <= 3,
                        "unexpected cache growth: {report:?}"
                    );
                    passes += 1;
                    tokio::task::yield_now().await;
                }
                assert!(passes > 0, "the gc loop must have run at least once");
                passes
            })
        };

        while let Some(result) = workers.join_next().await {
            result.expect("worker task must not panic");
        }
        done.store(true, Ordering::SeqCst);
        collector
            .await
            .expect("gc task must not panic under acquisition pressure");

        // Every spawned lease has been dropped, so a final pass must reclaim everything.
        let report = cache.collect_garbage().await.expect("final gc");
        assert_eq!(report.remaining_entries, 0, "{report:?}");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(cache.len(), 0);

        // Non-vacuity: with `max_entries = 0` + `max_age = ZERO` the collector evicts between
        // acquisitions, so the client must have been asked to materialize far more than the
        // three distinct commits. If it were exactly 3 the run would prove nothing.
        assert!(
            client.checkouts.load(Ordering::SeqCst) > 3,
            "the gc loop must force re-materialization for the race to be exercised"
        );
    }

    #[test]
    fn repo_hash_is_stable_thirty_two_hex_chars_and_url_sensitive() {
        let a = repo_hash(&normalize_repo_url(
            "https://github.com/ferris-cd/monorepo.git",
        ));
        let b = repo_hash(&normalize_repo_url(
            "https://github.com/ferris-cd/other.git",
        ));

        assert_eq!(a.len(), 32);
        assert!(
            a.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "repo hash must be lowercase hex: {a}"
        );
        assert_eq!(
            a,
            repo_hash(&normalize_repo_url(
                "https://github.com/ferris-cd/monorepo.git"
            )),
            "repo hash must be stable across calls"
        );
        assert_ne!(a, b, "different repositories must hash differently");

        // Conservative normalization: whitespace and trailing separators only.
        let trailing = "  https://github.com/ferris-cd/monorepo.git/  ";
        assert_eq!(
            normalize_repo_url(trailing),
            "https://github.com/ferris-cd/monorepo.git"
        );
        assert_eq!(repo_hash(&normalize_repo_url(trailing)), a);
        assert_ne!(normalize_repo_url("https://x/y"), "");
        assert_eq!(normalize_repo_url(""), "");
        // Degenerate inputs are left untouched rather than collapsed into an empty key.
        assert_eq!(normalize_repo_url("/"), "/");
        assert_eq!(normalize_repo_url("https://x/y///"), "https://x/y");
    }

    #[tokio::test]
    async fn invalid_sha_is_rejected_before_touching_disk() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (client, cache) = build_cache(work_root.path(), 8, TEST_MAX_AGE);
        let src = source(&fx);

        let err = cache
            .checkout(&src, "NOT-A-SHA", &RepoCredentials::Anonymous)
            .await
            .expect_err("invalid sha must be rejected");
        assert!(matches!(err, RepoError::InvalidRevision { .. }));
        assert_eq!(client.checkout_count(), 0);
        assert!(cache.is_empty());
    }

    #[tokio::test]
    async fn trailing_slash_url_variants_share_one_cache_entry() {
        let fx = build_fixture();
        let work_root = tempfile::tempdir().expect("create cache work root");
        let (_client, cache) = build_cache(work_root.path(), 8, TEST_MAX_AGE);
        let creds = RepoCredentials::Anonymous;

        let plain = source(&fx);
        let trailing = GitSource::new(
            format!("{}/", fx.bare_path.to_str().expect("utf8 path")),
            "main",
            "",
        );

        let a = cache.checkout(&plain, &fx.c2, &creds).await.expect("plain");
        let b = cache
            .checkout(&trailing, &fx.c2, &creds)
            .await
            .expect("trailing slash");

        // Trailing slashes normalize to the same key, so this is a cache hit.
        assert_eq!(a.root_dir(), b.root_dir());
        assert_eq!(cache.len(), 1);
    }

    /// [`GitClient`] that materializes a worktree containing a symlink escaping to
    /// `/etc/passwd`, so tests can prove the cache rejects it before publishing an entry.
    ///
    /// `filler_files` writes extra regular files into the tree purely to make the post-rename
    /// verification window wide enough for the concurrency regression test to hit it.
    #[cfg(unix)]
    struct MaliciousSymlinkClient {
        work_root: PathBuf,
        filler_files: usize,
        checkouts: AtomicUsize,
        seq: AtomicUsize,
    }

    #[cfg(unix)]
    impl MaliciousSymlinkClient {
        fn new(work_root: PathBuf, filler_files: usize) -> Self {
            Self {
                work_root,
                filler_files,
                checkouts: AtomicUsize::new(0),
                seq: AtomicUsize::new(0),
            }
        }
    }

    #[cfg(unix)]
    impl GitClient for MaliciousSymlinkClient {
        fn resolve_revision<'a>(
            &'a self,
            _src: &'a GitSource,
            _creds: &'a RepoCredentials,
        ) -> crate::repo::RepoFuture<'a, ResolvedRevision> {
            Box::pin(async move {
                Err(RepoError::RepositoryError {
                    message: "malicious stub does not resolve revisions".to_owned(),
                })
            })
        }

        fn checkout<'a>(
            &'a self,
            _src: &'a GitSource,
            sha: &'a str,
            _creds: &'a RepoCredentials,
        ) -> crate::repo::RepoFuture<'a, RepoCheckout> {
            self.checkouts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                validate_commit_sha(sha)?;
                let work_root = self.work_root.clone();
                let sha_owned = sha.to_owned();
                let filler_files = self.filler_files;
                let seq = self.seq.fetch_add(1, Ordering::SeqCst);
                tokio::task::spawn_blocking(move || {
                    std::fs::create_dir_all(&work_root)
                        .map_err(stub_io("creating malicious stub work_root"))?;
                    // Unique per call: the concurrency regression test materializes the same
                    // commit from several tasks, so a fixed name would collide.
                    let temp =
                        work_root.join(format!("ferriscd-evil-{}-{seq}", std::process::id()));
                    std::fs::create_dir_all(&temp)
                        .map_err(stub_io("creating malicious stub worktree"))?;
                    std::fs::write(temp.join("README.md"), "safe\n")
                        .map_err(stub_io("writing malicious stub README"))?;
                    for index in 0..filler_files {
                        std::fs::write(temp.join(format!("filler-{index}.txt")), "x")
                            .map_err(stub_io("writing malicious stub filler file"))?;
                    }
                    std::os::unix::fs::symlink("/etc/passwd", temp.join("evil-link"))
                        .map_err(stub_io("creating malicious symlink"))?;
                    Ok(RepoCheckout::new(temp, sha_owned))
                })
                .await
                .map_err(|join_err| RepoError::RepositoryError {
                    message: format!("malicious stub checkout task failed: {join_err}"),
                })?
            })
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cache_checkout_with_malicious_symlink_fails_and_leaves_no_entry() {
        let work_root = tempfile::tempdir().expect("create cache work root");
        let client = Arc::new(MaliciousSymlinkClient::new(
            work_root.path().to_path_buf(),
            0,
        ));
        let cache = RepoCache::new(
            Arc::clone(&client) as Arc<dyn GitClient>,
            RepoCacheConfig::new(work_root.path()),
        );
        let src = GitSource::new("https://example.test/ferris-cd/evil.git", "main", "");
        let sha = "0123456789abcdef0123456789abcdef01234567";

        let err = cache
            .checkout(&src, sha, &RepoCredentials::Anonymous)
            .await
            .expect_err("malicious symlink must be rejected before returning");

        assert!(
            matches!(err, RepoError::UnsafeSymlink { .. }),
            "expected UnsafeSymlink, got {err:?}"
        );
        assert!(!err.is_retryable());

        // No cache entry may be observable, and the published directory must be gone.
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        let dest = work_root
            .path()
            .join(WORKTREE_DIR)
            .join(repo_hash(&normalize_repo_url(&src.repo_url)))
            .join(sha);
        assert!(
            !dest.exists(),
            "rejected checkout directory must be removed: {}",
            dest.display()
        );
    }

    /// Regression test for the publish-before-verify window (Trap Guard C7 bypass).
    ///
    /// `EntryState::Ready` must not become observable until [`sanitize_worktree`] accepted the
    /// tree. The stub materializes a tree containing an escaping symlink plus enough filler
    /// files to widen the rename→verify window, and many callers race on the same commit. If
    /// the entry were published before verification, one of the lock-free `try_cache_hit`
    /// probes would lease the un-sanitized tree and return `Ok` (and a later failure could then
    /// delete the directory under that lease).
    ///
    /// Two kinds of task run concurrently for every round:
    ///
    /// * **callers** issue real [`RepoCache::checkout`] calls for the same sha and must never
    ///   receive `Ok`, and
    /// * **observers** hammer the private, lock-free `try_cache_hit` fast path for the whole
    ///   duration of the materialization; they never issue a checkout, so they are not parked
    ///   behind the per-repository lock and can actually land inside the rename→verify window
    ///   instead of at a materialization boundary.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn unverified_tree_is_never_leased_by_a_concurrent_checkout() {
        const CALLERS: usize = 4;
        const OBSERVERS: usize = 2;
        const ITERATIONS: usize = 3;
        const ROUNDS: usize = 2;

        let work_root = tempfile::tempdir().expect("create cache work root");
        let client = Arc::new(MaliciousSymlinkClient::new(
            work_root.path().to_path_buf(),
            1000,
        ));
        let cache = Arc::new(RepoCache::new(
            Arc::clone(&client) as Arc<dyn GitClient>,
            RepoCacheConfig::new(work_root.path()),
        ));
        let src = Arc::new(GitSource::new(
            "https://example.test/ferris-cd/evil.git",
            "main",
            "",
        ));
        let repo_hash = repo_hash(&normalize_repo_url(&src.repo_url));
        let repo_dir = work_root.path().join(WORKTREE_DIR).join(&repo_hash);

        for round in 1..=ROUNDS {
            let sha = format!("{round:040x}");

            let done = Arc::new(AtomicBool::new(false));
            let mut observers = JoinSet::new();
            for _ in 0..OBSERVERS {
                let cache = Arc::clone(&cache);
                let repo_hash = repo_hash.clone();
                let sha = sha.clone();
                let done = Arc::clone(&done);
                observers.spawn(async move {
                    let mut probes = 0usize;
                    while !done.load(Ordering::SeqCst) {
                        if let Ok(Some(lease)) = cache.try_cache_hit(&repo_hash, &sha) {
                            panic!(
                                "a cache hit was served for sha {sha} before its tree was \
                                 verified; leased {}",
                                lease.root_dir().display()
                            );
                        }
                        probes += 1;
                        tokio::task::yield_now().await;
                    }
                    assert!(probes > 0, "the observer never probed the cache");
                    probes
                });
            }

            let mut callers = JoinSet::new();
            for _ in 0..CALLERS {
                let cache = Arc::clone(&cache);
                let src = Arc::clone(&src);
                let sha = sha.clone();
                callers.spawn(async move {
                    for iteration in 0..ITERATIONS {
                        let result = cache
                            .checkout(&src, &sha, &RepoCredentials::Anonymous)
                            .await;
                        match result {
                            Ok(checkout) => panic!(
                                "no checkout call may ever succeed for an un-sanitized tree \
                                 (iteration {iteration}, sha {sha}): leaked {}",
                                checkout.root_dir().display()
                            ),
                            Err(err) => {
                                assert!(
                                    matches!(err, RepoError::UnsafeSymlink { .. }),
                                    "expected a terminal UnsafeSymlink, got {err:?}"
                                );
                                assert!(!err.is_retryable(), "must be terminal: {err}");
                            }
                        }
                        tokio::task::yield_now().await;
                    }
                });
            }

            while let Some(result) = callers.join_next().await {
                result.expect("checkout task must not panic");
            }
            done.store(true, Ordering::SeqCst);
            while let Some(result) = observers.join_next().await {
                result.expect("observer task must not panic");
            }

            assert!(cache.is_empty(), "round {round} leaked a cache entry");
            assert_eq!(cache.len(), 0);
            let dest = repo_dir.join(&sha);
            assert!(
                !dest.exists(),
                "round {round} left the rejected directory behind: {}",
                dest.display()
            );
        }

        // No leased directory and no entry may survive any of the failed materializations.
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        match std::fs::read_dir(&repo_dir) {
            Ok(entries) => assert_eq!(
                entries.count(),
                0,
                "rejected materializations must not leave directories in {}",
                repo_dir.display()
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("reading {}: {err}", repo_dir.display()),
        }
        // Non-vacuity: the window was actually exercised, many times over.
        assert!(
            client.checkouts.load(Ordering::SeqCst) >= CALLERS * ITERATIONS,
            "the race must have driven repeated materializations"
        );
    }

    /// The configurable budgets must be enforced by the cache end-to-end, and a rejected tree
    /// must never be published.
    #[tokio::test]
    async fn worktree_limits_reject_a_benign_tree_without_publishing_an_entry() {
        let work_root = tempfile::tempdir().expect("create cache work root");
        let client = Arc::new(StubClient::with_extra_files(
            work_root.path().to_path_buf(),
            1,
        ));
        let config = RepoCacheConfig::new(work_root.path())
            .with_worktree_limits(WorktreeLimits::new().with_max_files(1));
        let cache = RepoCache::new(Arc::clone(&client) as Arc<dyn GitClient>, config);
        let src = GitSource::new("https://example.test/ferris-cd/stub.git", "main", "apps");
        let sha = format!("{:040x}", 1);

        let err = cache
            .checkout(&src, &sha, &RepoCredentials::Anonymous)
            .await
            .expect_err("a tree over the configured max_files budget must be rejected");
        assert!(
            matches!(err, RepoError::CheckoutLimitExceeded { .. }),
            "expected CheckoutLimitExceeded, got {err:?}"
        );
        assert!(!err.is_retryable(), "a budget violation must be terminal");

        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
        let dest = work_root
            .path()
            .join(WORKTREE_DIR)
            .join(repo_hash(&normalize_repo_url(&src.repo_url)))
            .join(&sha);
        assert!(
            !dest.exists(),
            "a rejected checkout directory must be removed: {}",
            dest.display()
        );
    }
}
