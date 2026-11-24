//! Persistent per-URL bare mirror / object store.
//!
//! [`super::GixGitClient`] materializes every checkout from a persistent **bare repository**
//! keyed by the normalized `repo_url` under `<work_root>/mirrors/<repo_hash>`. The mirror is
//! initialized and fetched once; later materializations reuse its objects instead of re-fetching
//! shared history from the remote.
//!
//! # What lives here
//!
//! * [`MirrorLimits`] — the reclamation bounds (`max_entries`, `max_age`).
//! * [`MirrorGcReport`] — the outcome of a reclamation pass.
//! * [`MirrorStore`] — the per-`GixGitClient` in-memory bookkeeping: one **blocking** per-mirror
//!   mutex (so concurrent clients never corrupt a mirror), initialization/fetch counters, and the
//!   reclamation implementation.
//! * Filesystem helpers for the mirror layout and the `.ferriscd-last-used` marker used to age
//!   mirrors out.
//!
//! All `gix` repository opening/init/fetch logic stays in [`super::gix_client`]; this module is
//! deliberately free of `gix` types so its reclamation logic can be unit-tested with plain
//! filesystem fixtures.
//!
//! # Crash safety & reclamation
//!
//! First-time creation is *init + fetch into a temporary directory, then an atomic `rename(2)`
//! into `<work_root>/mirrors/<repo_hash>`*. A failed first-time operation drops the temporary
//! directory and never leaves a partial mirror; if the final directory already exists it is
//! reused. Later updates fetch **in place** into the existing mirror, so a failed update can
//! never delete a usable existing mirror.
//!
//! A mirror is considered *in use* while its per-mirror blocking mutex is held by an active
//! [`super::GixGitClient`] operation. [`MirrorStore::collect_garbage`] only removes mirrors it can
//! `try_lock` (i.e. not in use) whose last-use marker is older than [`MirrorLimits::max_age`],
//! plus the least-recently-used mirrors needed to satisfy [`MirrorLimits::max_entries`].
//!
//! # Permission contract
//!
//! A mirror's `config` and packed objects must never be readable by other local users. The
//! no-`work_root` mirror root is therefore a **process-private** `tempfile` directory created
//! `0700` once and cached for the process lifetime — it is never the shared, world-readable
//! `/tmp/ferriscd-mirrors` directory. On every first-time publish (after the atomic `rename(2)`),
//! the mirror tree is walked and tightened to `0700` directories / `0600` files so a bare
//! repository's `config`, `objects/`, and `refs/` are private. Reopened mirrors are trusted and
//! not re-walked on every operation.
//!
//! # Credential keying
//!
//! Mirrors are keyed by normalized `repo_url` only — there is deliberately no credential-generation
//! component in the key. That is safe because (1) mirror reuse is content-addressed: Git objects
//! are immutable and addressed by SHA, so a credential change can never make a cached object stale;
//! (2) no credential material is ever persisted in a mirror (credentials flow only through the
//! per-operation callback in [`super::auth`]); and (3) any object missing from the mirror is
//! re-fetched with the credentials supplied to the current operation.
//!
//! # Reclamation limits
//!
//! [`MirrorLimits`] bounds reclamation by **count** ([`MirrorLimits::max_entries`]) and **idle
//! age** ([`MirrorLimits::max_age`]) only; there is intentionally no byte-size budget. A single
//! monorepo mirror can therefore grow to the full size of its history.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dashmap::DashMap;
use tempfile::TempDir;

use super::error::RepoError;

/// Sub-directory of the `GixGitClient` work root that holds persistent bare mirrors.
pub(crate) const MIRROR_DIR: &str = "mirrors";

/// File name of the per-mirror last-use marker (contents are Unix seconds).
const LAST_USED_FILE: &str = ".ferriscd-last-used";

/// Successful publishes between opportunistic mirror reclamation passes.
pub(crate) const MIRROR_GC_INTERVAL: usize = 16;

/// Prefix of the process-private default mirror root created when no `work_root` is configured.
const DEFAULT_MIRROR_ROOT_PREFIX: &str = "ferriscd-mirrors-";

/// Default maximum number of mirrors retained before reclamation evicts the least-recently-used.
pub const DEFAULT_MIRROR_MAX_ENTRIES: usize = 32;

/// Default maximum idle age of a mirror before it becomes eligible for reclamation.
pub const DEFAULT_MIRROR_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Bounds controlling [`MirrorStore`] reclamation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MirrorLimits {
    /// Maximum number of mirrors retained after a reclamation pass.
    ///
    /// `0` evicts every mirror that is not currently in use.
    pub max_entries: usize,
    /// Maximum **idle** age of a mirror before it becomes eligible for reclamation, measured from
    /// its most recent successful use. [`Duration::ZERO`] therefore evicts every unused mirror on
    /// the next pass.
    pub max_age: Duration,
}

impl Default for MirrorLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MIRROR_MAX_ENTRIES,
            max_age: DEFAULT_MIRROR_MAX_AGE,
        }
    }
}

impl MirrorLimits {
    /// Creates the default bounds ([`DEFAULT_MIRROR_MAX_ENTRIES`], [`DEFAULT_MIRROR_MAX_AGE`]).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum number of retained mirrors.
    #[must_use]
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Sets the maximum idle age of a mirror.
    #[must_use]
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }
}

/// Outcome of a [`super::GixGitClient::collect_mirror_garbage`] pass.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MirrorGcReport {
    /// Number of mirrors removed during this pass.
    pub removed_entries: usize,
    /// Number of mirrors still present on disk when the pass finished (including in-use ones).
    pub remaining_entries: usize,
    /// Human-readable descriptions of directory deletions that failed.
    pub failures: Vec<String>,
}

/// One on-disk mirror discovered during a reclamation pass.
struct MirrorEntry {
    /// The mirror directory name (the repository hash), also the blocking-lock key.
    key: String,
    /// Absolute path of the mirror directory.
    path: PathBuf,
    /// Last-use timestamp in Unix seconds, or `None` when the marker is absent/unreadable.
    last_used: Option<u64>,
}

/// Per-`GixGitClient` mirror bookkeeping.
///
/// [`GixGitClient`](super::gix_client::GixGitClient) clones share one `Arc<MirrorStore>`, so all
/// clones of a client serialize on the same per-mirror locks and report the same counters.
/// Separate [`GixGitClient`](super::gix_client::GixGitClient) instances (or separate processes)
/// each own an independent `MirrorStore`, so they do **not** share these locks and must not share
/// a `work_root`.
#[derive(Debug)]
pub(crate) struct MirrorStore {
    limits: MirrorLimits,
    /// One blocking mutex per mirror (keyed by repository hash). Held for the duration of one
    /// blocking fetch/materialize operation; never held across an `.await`.
    ///
    /// Entries are pruned (only when no operation holds a reference to the `Arc`) after their
    /// mirror directory is removed, so the map stays bounded by the number of mirrors ever held
    /// concurrently rather than by the total number of distinct repositories ever touched.
    locks: DashMap<String, Arc<Mutex<()>>>,
    /// Number of times a first-time mirror was successfully published, for tests/observability.
    initializations: AtomicUsize,
    /// Number of remote fetches performed into a mirror (for tests/observability).
    fetches: AtomicUsize,
    /// Number of successful mirror publishes since the last opportunistic reclamation pass.
    publishes: AtomicUsize,
}

impl Default for MirrorStore {
    fn default() -> Self {
        Self::new(MirrorLimits::default())
    }
}

impl MirrorStore {
    /// Creates a mirror store with `limits`.
    pub(crate) fn new(limits: MirrorLimits) -> Self {
        Self {
            limits,
            locks: DashMap::new(),
            initializations: AtomicUsize::new(0),
            fetches: AtomicUsize::new(0),
            publishes: AtomicUsize::new(0),
        }
    }

    /// Returns (creating on first use) the blocking mutex guarding `repo_hash`.
    pub(crate) fn lock_for(&self, repo_hash: &str) -> Arc<Mutex<()>> {
        if let Some(existing) = self.locks.get(repo_hash) {
            return Arc::clone(existing.value());
        }
        self.locks
            .entry(repo_hash.to_owned())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .value()
            .clone()
    }

    /// Records one successful first-time mirror publish.
    pub(crate) fn record_initialization(&self) {
        self.initializations.fetch_add(1, Ordering::SeqCst);
    }

    /// Records one remote fetch performed into a mirror.
    pub(crate) fn record_fetch(&self) {
        self.fetches.fetch_add(1, Ordering::SeqCst);
    }

    /// Records one successful mirror publish and reports whether it is time for an opportunistic
    /// reclamation pass (every [`MIRROR_GC_INTERVAL`] publishes).
    pub(crate) fn record_publish(&self) -> bool {
        self.publishes.fetch_add(1, Ordering::SeqCst) % MIRROR_GC_INTERVAL == MIRROR_GC_INTERVAL - 1
    }

    /// Returns how many first-time mirrors were created.
    #[must_use]
    pub(crate) fn initializations(&self) -> usize {
        self.initializations.load(Ordering::SeqCst)
    }

    /// Returns how many remote fetches were performed into mirrors.
    #[must_use]
    pub(crate) fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    /// Reclaims unused mirrors under `mirror_root`.
    ///
    /// Runs synchronously (callers invoke it inside `tokio::task::spawn_blocking`). A mirror is
    /// eligible only when its blocking mutex is **not** held (so an active operation can never have
    /// its mirror deleted) and it is either idle past [`MirrorLimits::max_age`] or must be evicted
    /// to satisfy [`MirrorLimits::max_entries`].
    pub(crate) fn collect_garbage(&self, mirror_root: &Path) -> MirrorGcReport {
        let mut report = MirrorGcReport::default();

        let entries = match list_mirror_entries(mirror_root) {
            Ok(entries) => entries,
            Err(message) => {
                report.failures.push(message);
                return report;
            }
        };

        let now = unix_secs();
        let max_age_secs = self.limits.max_age.as_secs();

        // Phase 1 — TTL: remove expired mirrors that are not currently in use. A mirror whose
        // last-use marker is missing/unreadable is treated as idle so a stray directory can never
        // be pinned forever.
        let mut remaining: Vec<MirrorEntry> = Vec::new();
        for entry in entries {
            let expired = match entry.last_used {
                Some(last_used) => now.saturating_sub(last_used) >= max_age_secs,
                None => true,
            };
            if !expired {
                remaining.push(entry);
                continue;
            }
            match self.try_remove_mirror(&entry) {
                Ok(true) => report.removed_entries += 1,
                Ok(false) => remaining.push(entry), // in use: retain
                Err(message) => {
                    report.failures.push(message);
                    remaining.push(entry);
                }
            }
        }

        // Phase 2 — size bound: evict least-recently-used mirrors that are not in use until the
        // retained count is within `max_entries`. Walking oldest-first keeps the most-recently-used
        // mirrors and skips (retains) any mirror whose blocking lock is currently held.
        remaining.sort_by_key(|entry| entry.last_used.unwrap_or(0));
        let mut index = 0usize;
        while index < remaining.len() && remaining.len() > self.limits.max_entries {
            match self.try_remove_mirror(&remaining[index]) {
                Ok(true) => {
                    report.removed_entries += 1;
                    remaining.remove(index);
                    // Do not advance: the next (now-oldest) entry shifted into `index`.
                }
                Ok(false) => index += 1,
                Err(message) => {
                    report.failures.push(message);
                    index += 1;
                }
            }
        }

        report.remaining_entries = remaining.len();
        report
    }

    /// Removes one mirror unless it is currently in use.
    ///
    /// Returns `Ok(true)` when the directory is gone, `Ok(false)` when the mirror is in use (and
    /// therefore left untouched), and `Err` when deletion failed.
    fn try_remove_mirror(&self, entry: &MirrorEntry) -> Result<bool, String> {
        let lock = self.lock_for(&entry.key);
        let guard = match lock.try_lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(false),
        };

        let removed = match std::fs::remove_dir_all(&entry.path) {
            Ok(()) => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(err) => {
                return Err(format!(
                    "failed to remove mirror '{}': {err}",
                    entry.path.display()
                ));
            }
        };

        // The mirror is gone and no in-flight operation can still be using it (we hold its lock).
        // Drop our local lock handle before pruning: the prune is safe only when the map holds the
        // last `Arc` reference, and this local clone would otherwise keep that from ever being true.
        drop(guard);
        drop(lock);
        self.prune_lock_if_unreferenced(&entry.key);

        Ok(removed)
    }

    /// Drops the per-mirror lock entry when no operation holds a reference to it.
    ///
    /// Called only after a mirror directory has been removed. Removing the map entry is safe only
    /// while the stored `Arc` has no other strong references (i.e. no operation has cloned it and
    /// is between [`Self::lock_for`] and `lock()`); [`DashMap::remove_if`] evaluates that check
    /// atomically under the shard lock, so a concurrent [`Self::lock_for`] cannot clone the same
    /// `Arc` in the same instant.
    fn prune_lock_if_unreferenced(&self, key: &str) {
        self.locks
            .remove_if(key, |_key, lock| Arc::strong_count(lock) == 1);
    }
}

/// Lists candidate mirror directories directly beneath `mirror_root`.
fn list_mirror_entries(mirror_root: &Path) -> Result<Vec<MirrorEntry>, String> {
    let read = match std::fs::read_dir(mirror_root) {
        Ok(read) => read,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!(
                "reading mirror directory '{}': {err}",
                mirror_root.display()
            ));
        }
    };

    let mut entries = Vec::new();
    for entry in read {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                return Err(format!(
                    "reading mirror directory entry in '{}': {err}",
                    mirror_root.display()
                ));
            }
        };

        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_mirror_dir_name(&name) {
            continue;
        }
        let is_dir = match entry.file_type() {
            Ok(file_type) => file_type.is_dir(),
            Err(_) => continue,
        };
        if !is_dir {
            continue;
        }

        let path = entry.path();
        entries.push(MirrorEntry {
            key: name,
            path,
            last_used: read_last_used_secs(&entry.path()),
        });
    }
    Ok(entries)
}

/// Returns `true` when `name` is a 32-character lowercase hex digest (a repository hash).
fn is_mirror_dir_name(name: &str) -> bool {
    name.len() == 32
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns the absolute mirror root for a client `work_root`.
///
/// With a `work_root` this is `<work_root>/mirrors`. Without one it is a **process-private**,
/// `0700` directory created lazily once and cached for the process lifetime (see
/// [`default_mirror_root`]).
pub(crate) fn mirror_root(work_root: Option<&Path>) -> Result<PathBuf, RepoError> {
    match work_root {
        Some(root) => Ok(root.join(MIRROR_DIR)),
        None => default_mirror_root(),
    }
}

/// Returns the absolute directory of the mirror for `repo_hash`.
pub(crate) fn mirror_dir(work_root: Option<&Path>, repo_hash: &str) -> Result<PathBuf, RepoError> {
    Ok(mirror_root(work_root)?.join(repo_hash))
}

/// Creates (once per process) and returns the private default mirror root.
///
/// The returned `TempDir` is intentionally leaked into a static so it — and its `0700` mode — live
/// for the whole process; it is removed by the OS on exit like any other temp directory.
fn default_mirror_root() -> Result<PathBuf, RepoError> {
    static DEFAULT_ROOT: Mutex<Option<TempDir>> = Mutex::new(None);

    let mut guard = DEFAULT_ROOT
        .lock()
        .map_err(|_| RepoError::RepositoryError {
            message: "default mirror root lock was poisoned".to_owned(),
        })?;
    if let Some(dir) = guard.as_ref() {
        return Ok(dir.path().to_path_buf());
    }

    let dir = tempfile::Builder::new()
        .prefix(DEFAULT_MIRROR_ROOT_PREFIX)
        .tempdir()
        .map_err(|source| RepoError::Io {
            context: "creating private default mirror root".to_owned(),
            source,
        })?;
    make_tree_private(dir.path())?;
    let path = dir.path().to_path_buf();
    *guard = Some(dir);
    Ok(path)
}

/// Recursively tightens `path` to owner-only access.
///
/// Directories become `0700` and regular files become `0600`. Symbolic links are left untouched
/// (a bare Git mirror must not contain symlinks, and following one here could traverse outside the
/// mirror). Used both for the process-private default root and for a freshly published mirror.
#[cfg(unix)]
pub(crate) fn make_tree_private(path: &Path) -> Result<(), RepoError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::symlink_metadata(path).map_err(|source| RepoError::Io {
        context: format!("inspecting '{}' to set private permissions", path.display()),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions).map_err(|source| RepoError::Io {
        context: format!("setting private permissions on '{}'", path.display()),
        source,
    })?;

    if metadata.is_dir() {
        let entries = std::fs::read_dir(path).map_err(|source| RepoError::Io {
            context: format!("reading '{}' to set private permissions", path.display()),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| RepoError::Io {
                context: format!(
                    "reading entry in '{}' to set private permissions",
                    path.display()
                ),
                source,
            })?;
            make_tree_private(&entry.path())?;
        }
    }
    Ok(())
}

/// On non-Unix platforms there are no POSIX mode bits to tighten; this is a no-op.
#[cfg(not(unix))]
pub(crate) fn make_tree_private(_path: &Path) -> Result<(), RepoError> {
    Ok(())
}

/// Writes the current Unix timestamp into the mirror's last-use marker.
pub(crate) fn touch_last_used(mirror_dir: &Path) -> Result<(), RepoError> {
    let marker = mirror_dir.join(LAST_USED_FILE);
    std::fs::write(&marker, unix_secs().to_string()).map_err(|source| RepoError::Io {
        context: format!("writing mirror last-used marker '{}'", marker.display()),
        source,
    })
}

/// Reads the mirror's last-use timestamp, or `None` when the marker is absent/unreadable.
fn read_last_used_secs(mirror_dir: &Path) -> Option<u64> {
    let body = std::fs::read_to_string(mirror_dir.join(LAST_USED_FILE)).ok()?;
    body.trim().parse::<u64>().ok()
}

/// Current wall-clock time in whole seconds (0 if the clock precedes the Unix epoch).
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(limits: MirrorLimits) -> MirrorStore {
        MirrorStore::new(limits)
    }

    fn make_mirror(root: &Path, name: &str, last_used: Option<u64>) -> PathBuf {
        let path = root.join(name);
        std::fs::create_dir_all(&path).expect("create mirror dir");
        std::fs::write(path.join("config"), "core\n\tbare = true\n").expect("write mirror config");
        if let Some(seconds) = last_used {
            std::fs::write(path.join(LAST_USED_FILE), seconds.to_string())
                .expect("write last-used marker");
        }
        path
    }

    #[test]
    fn mirror_limits_default_and_builder_round_trip() {
        let limits = MirrorLimits::new();
        assert_eq!(limits.max_entries, DEFAULT_MIRROR_MAX_ENTRIES);
        assert_eq!(limits.max_age, DEFAULT_MIRROR_MAX_AGE);
        assert_eq!(
            limits.with_max_entries(7).with_max_age(Duration::ZERO),
            MirrorLimits {
                max_entries: 7,
                max_age: Duration::ZERO
            }
        );
    }

    #[test]
    fn mirror_dir_names_are_strict_32_lowercase_hex() {
        for (name, expected) in [
            ("0123456789abcdef0123456789abcdef", true),
            ("0123456789ABCDEF0123456789abcdef", false),
            ("0123456789abcdef0123456789abcde", false),
            ("ferriscd-git-abc123", false),
            ("../0123456789abcdef0123456789abcdef", false),
        ] {
            assert_eq!(
                is_mirror_dir_name(name),
                expected,
                "unexpected for {name:?}"
            );
        }
    }

    #[test]
    fn collect_garbage_removes_unused_expired_mirror_and_keeps_in_use_one() {
        let root = tempfile::tempdir().expect("create mirror root");
        let store = store_with(
            MirrorLimits::new()
                .with_max_entries(16)
                .with_max_age(Duration::ZERO),
        );

        let now = super::unix_secs();
        let expired = make_mirror(root.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Some(now));
        let active = make_mirror(root.path(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Some(now));

        // Hold the active mirror's blocking lock to simulate an in-flight operation.
        let lock = store.lock_for("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let _guard = lock.lock().expect("lock active mirror");

        let report = store.collect_garbage(root.path());
        assert_eq!(report.removed_entries, 1);
        assert_eq!(report.remaining_entries, 1);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(!expired.exists(), "unused expired mirror must be removed");
        assert!(active.is_dir(), "in-use mirror must be retained");
    }

    #[test]
    fn collect_garbage_respects_max_entries_and_skips_in_use() {
        let root = tempfile::tempdir().expect("create mirror root");
        let store = store_with(
            MirrorLimits::new()
                .with_max_entries(1)
                .with_max_age(DEFAULT_MIRROR_MAX_AGE),
        );

        // Both markers are recent (within max_age), so the size bound — not TTL — must drive the
        // eviction: the older mirror is the least-recently-used and gets removed.
        let now = super::unix_secs();
        let newest = make_mirror(root.path(), "11111111111111111111111111111111", Some(now));
        let older = make_mirror(
            root.path(),
            "22222222222222222222222222222222",
            Some(now.saturating_sub(100)),
        );

        let lock = store.lock_for("11111111111111111111111111111111");
        let _guard = lock.lock().expect("lock newest mirror");

        // Even though `older` is within max_age, the size bound evicts it; the in-use newest mirror
        // is retained.
        let report = store.collect_garbage(root.path());
        assert_eq!(report.removed_entries, 1);
        assert_eq!(report.remaining_entries, 1);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(
            !older.exists(),
            "least-recently-used mirror must be evicted"
        );
        assert!(newest.is_dir(), "in-use mirror must survive the size bound");
    }

    #[test]
    fn collect_garbage_ignores_non_mirror_directories_and_missing_root() {
        let root = tempfile::tempdir().expect("create mirror root");
        // A non-mirror directory name must never be reclaimed as a mirror.
        std::fs::create_dir_all(root.path().join("ferriscd-git-tmp")).expect("mkdir temp");
        std::fs::write(root.path().join("ferriscd-git-tmp/x"), "x").expect("write temp file");

        let store = store_with(
            MirrorLimits::new()
                .with_max_entries(0)
                .with_max_age(Duration::ZERO),
        );
        let report = store.collect_garbage(root.path());
        assert_eq!(report.removed_entries, 0);
        assert_eq!(report.remaining_entries, 0);
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert!(
            root.path().join("ferriscd-git-tmp").is_dir(),
            "non-mirror directory must be ignored"
        );

        let missing = tempfile::tempdir().expect("create parent");
        let report = store.collect_garbage(&missing.path().join("does-not-exist"));
        assert_eq!(report.removed_entries, 0);
        assert_eq!(report.remaining_entries, 0);
        assert!(report.failures.is_empty());
    }

    #[test]
    fn last_used_marker_round_trips() {
        let dir = tempfile::tempdir().expect("create mirror dir");
        assert_eq!(read_last_used_secs(dir.path()), None);

        touch_last_used(dir.path()).expect("touch last used");
        let seconds = read_last_used_secs(dir.path()).expect("read last used");
        assert!(seconds > 0, "last-used marker must hold a Unix timestamp");
    }

    #[cfg(unix)]
    #[test]
    fn default_mirror_root_is_process_private_and_cached() {
        use std::os::unix::fs::PermissionsExt;

        let root = mirror_root(None).expect("default mirror root");
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .expect("utf8 default mirror root name");
        assert!(
            name.starts_with(DEFAULT_MIRROR_ROOT_PREFIX),
            "unexpected default mirror root name: {name}"
        );

        let mode = std::fs::metadata(&root)
            .expect("stat default mirror root")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "default mirror root must be owner-only: {mode:#o}"
        );

        assert_eq!(
            mirror_root(None).expect("cached default mirror root"),
            root,
            "the process-private default mirror root must be cached"
        );
    }
}
