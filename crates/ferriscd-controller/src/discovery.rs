//! API discovery cache with a TTL and a coalesced (single-flight) refresh.
//!
//! Resolving a dynamic GVK from scratch on every reconcile hammers the API server, while
//! caching a snapshot forever breaks the moment a CRD is installed mid-sync (CRD + CR in
//! one bundle, trap T6). [`DiscoveryCache`] therefore keeps a snapshot under
//! `Arc<tokio::sync::RwLock<CachedDiscovery>>` with a TTL (5 minutes by default) and
//! exposes two refresh entry points:
//!
//! * [`DiscoveryCache::ensure_fresh`] — refresh only once the TTL has expired,
//! * [`DiscoveryCache::invalidate_and_refresh`] — force a refresh (e.g. right before
//!   applying an in-bundle `CustomResourceDefinition`).
//!
//! Both are coalesced through a single [`tokio::sync::Mutex`] plus a generation counter,
//! so N concurrent misses (or N concurrent invalidations) trigger **one** API-server
//! round trip instead of N. Re-reading discovery for every resource in a 500-object bundle
//! is exactly the failure mode this guards against.
//!
//! Two lookups are offered:
//!
//! * [`DiscoveryCache::resolve`] (async) returns the `ApiResource` + `ApiCapabilities`
//!   needed to build a dynamic `Api`,
//! * [`ScopeLookup::scope_of`] (sync) answers "is this GVK namespaced or cluster-scoped?"
//!   from a derived index, so offline scope normalization ([`crate::scope`]) never blocks
//!   a Tokio worker.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant};

use kube::core::gvk::GroupVersionKind;
use kube::discovery::{ApiCapabilities, ApiResource, Scope};
use tokio::sync::{Mutex, RwLock};

use crate::{read_recover, write_recover};

/// Default snapshot TTL (5 minutes).
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// Returned by [`DiscoveryCache::kube_version`] before the first successful refresh.
pub const UNKNOWN_KUBE_VERSION: &str = "unknown";

/// Boxed result of a [`DiscoverySource`] round trip.
pub type DiscoveryFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DiscoverySnapshot, DiscoveryError>> + Send + 'a>>;

/// A discovered API resource together with its capabilities.
#[derive(Debug, Clone)]
pub struct DiscoveredResource {
    /// Group/version/kind plus the plural name needed by the dynamic `Api` API.
    pub api_resource: ApiResource,
    /// Scope, subresources, and supported verbs.
    pub capabilities: ApiCapabilities,
}

/// One complete discovery round trip.
#[derive(Debug, Clone, Default)]
pub struct DiscoverySnapshot {
    /// `gitVersion` of the API server (`v1.35.0`, ...); fed to Helm `--kube-version`.
    pub kube_version: String,
    /// Every `group/version/kind` the API server serves, one entry per served version.
    ///
    /// Older served versions of a kind are kept alongside the most stable one (`kube`'s
    /// `resources_by_stability()` drops them), because [`CachedDiscovery::resolve`]
    /// matches an exact group + version + kind.
    pub resources: Vec<DiscoveredResource>,
}

impl DiscoverySnapshot {
    /// Builds an empty snapshot reporting `kube_version`.
    #[must_use]
    pub fn new(kube_version: impl Into<String>) -> Self {
        Self {
            kube_version: kube_version.into(),
            resources: Vec::new(),
        }
    }

    /// Adds a discovered resource (builder style).
    #[must_use]
    pub fn with_resource(
        mut self,
        api_resource: ApiResource,
        capabilities: ApiCapabilities,
    ) -> Self {
        self.resources.push(DiscoveredResource {
            api_resource,
            capabilities,
        });
        self
    }

    /// Resolves an exact group + version + kind match.
    #[must_use]
    pub fn resolve(&self, gvk: &GroupVersionKind) -> Option<(ApiResource, ApiCapabilities)> {
        self.resources
            .iter()
            .find(|resource| {
                resource.api_resource.group == gvk.group
                    && resource.api_resource.version == gvk.version
                    && resource.api_resource.kind == gvk.kind
            })
            .map(|resource| (resource.api_resource.clone(), resource.capabilities.clone()))
    }
}

/// The cached discovery snapshot.
///
/// `fetched_at` stays `None` until the first successful fetch, so an empty cache is always
/// stale and can never masquerade as a fresh snapshot that legitimately lacks a kind.
#[derive(Debug, Clone, Default)]
pub struct CachedDiscovery {
    fetched_at: Option<Instant>,
    resources: Vec<DiscoveredResource>,
}

impl CachedDiscovery {
    /// Builds an empty (always stale) snapshot.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// When this snapshot was fetched, if it ever was.
    #[must_use]
    pub fn fetched_at(&self) -> Option<Instant> {
        self.fetched_at
    }

    /// Returns whether the snapshot holds no resources.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    /// Returns whether the snapshot must be refreshed at `now` for a `ttl` cache.
    #[must_use]
    pub fn is_stale(&self, now: Instant, ttl: Duration) -> bool {
        match self.fetched_at {
            None => true,
            Some(fetched_at) => now.saturating_duration_since(fetched_at) >= ttl,
        }
    }

    /// Resolves an exact group + version + kind match against the cached resources.
    #[must_use]
    pub fn resolve(&self, gvk: &GroupVersionKind) -> Option<(ApiResource, ApiCapabilities)> {
        self.resources
            .iter()
            .find(|resource| {
                resource.api_resource.group == gvk.group
                    && resource.api_resource.version == gvk.version
                    && resource.api_resource.kind == gvk.kind
            })
            .map(|resource| (resource.api_resource.clone(), resource.capabilities.clone()))
    }

    fn replace(&mut self, snapshot: &DiscoverySnapshot, fetched_at: Instant) {
        self.resources.clone_from(&snapshot.resources);
        self.fetched_at = Some(fetched_at);
    }
}

/// Synchronous scope lookup over already-cached discovery data.
///
/// Implemented by [`DiscoveryCache`] for production and by plain maps in tests. Scope
/// normalization is a pure, offline step: it must never await (and thereby never hog a
/// Tokio worker) while deciding whether to inject a namespace.
pub trait ScopeLookup {
    /// Returns the scope of `gvk` when the cached snapshot knows its group + kind.
    fn scope_of(&self, gvk: &GroupVersionKind) -> Option<Scope>;
}

/// Source of discovery snapshots.
///
/// Production uses the live API server ([`KubeDiscoverySource`]); tests use a scripted
/// fake so TTL and single-flight behaviour are provable without a cluster.
pub trait DiscoverySource: Send + Sync + 'static {
    /// Performs one full discovery round trip.
    fn fetch(&self) -> DiscoveryFuture<'_>;
}

/// Discovery errors.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The API server could not be reached or discovery failed.
    #[error("Kubernetes API discovery failed: {message}")]
    Refresh {
        /// Underlying failure description.
        message: String,
    },

    /// Discovery succeeded but the API server does not serve the requested kind.
    ///
    /// Also produced when a GVK genuinely does not exist; callers treat this exactly like
    /// a deleted resource when cleaning up (T05.3).
    #[error("no matches for kind {kind} in version {version} (group {group:?})")]
    NoMatchesForKind {
        /// API group (empty for the core group).
        group: String,
        /// API version.
        version: String,
        /// Resource kind.
        kind: String,
    },
}

impl DiscoveryError {
    /// Returns `true` for [`DiscoveryError::NoMatchesForKind`].
    #[must_use]
    pub fn is_no_matches_for_kind(&self) -> bool {
        matches!(self, Self::NoMatchesForKind { .. })
    }
}

/// Discovery fetched from the live API server.
#[derive(Clone)]
pub struct KubeDiscoverySource {
    client: kube::Client,
}

impl KubeDiscoverySource {
    /// Builds a source over `client`.
    #[must_use]
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

impl DiscoverySource for KubeDiscoverySource {
    fn fetch(&self) -> DiscoveryFuture<'_> {
        Box::pin(async move {
            let info =
                self.client
                    .apiserver_version()
                    .await
                    .map_err(|err| DiscoveryError::Refresh {
                        message: err.to_string(),
                    })?;

            // Aggregated discovery is two requests instead of N+2 (Kubernetes 1.26+);
            // fall back to per-group discovery for older API servers.
            let discovery = match kube::discovery::Discovery::new(self.client.clone())
                .run_aggregated()
                .await
            {
                Ok(discovery) => discovery,
                Err(err) => {
                    tracing::debug!(
                        error = %err,
                        "aggregated discovery unavailable; falling back to per-group discovery"
                    );
                    kube::discovery::Discovery::new(self.client.clone())
                        .run()
                        .await
                        .map_err(|err| DiscoveryError::Refresh {
                            message: err.to_string(),
                        })?
                }
            };

            let mut snapshot = DiscoverySnapshot::new(info.git_version);
            for group in discovery.groups() {
                append_all_versions(&mut snapshot, group.versions(), |version| {
                    group.versioned_resources(version)
                });
            }
            Ok(snapshot)
        })
    }
}

/// Appends every resource served by one API group at **all** of its served versions.
///
/// `kube`'s `ApiGroup::resources_by_stability()` keeps only the most stable version of each
/// kind, but dynamic resolution matches an exact `group + version + kind`: a manifest pinned
/// to an older served version (`autoscaling/v1` beside `autoscaling/v2`, or a CRD serving
/// `v1alpha1` + `v1`) must still resolve. Otherwise cleanup treats the kind as already
/// deleted (T05.3) and apply fails terminally with `NoMatchesForKind`.
///
/// The per-version accessor is injected so the union over versions stays unit-testable
/// without a live API server.
fn append_all_versions<'a, I, F>(snapshot: &mut DiscoverySnapshot, versions: I, resources_at: F)
where
    I: IntoIterator<Item = &'a str>,
    F: Fn(&str) -> Vec<(ApiResource, ApiCapabilities)>,
{
    for version in versions {
        for (api_resource, capabilities) in resources_at(version) {
            snapshot.resources.push(DiscoveredResource {
                api_resource,
                capabilities,
            });
        }
    }
}

/// Derived, synchronously readable view of the last snapshot.
#[derive(Debug, Default)]
struct DiscoveryIndex {
    kube_version: String,
    scopes: HashMap<(String, String), Scope>,
}

impl DiscoveryIndex {
    fn replace(&mut self, snapshot: &DiscoverySnapshot) {
        self.kube_version.clone_from(&snapshot.kube_version);
        self.scopes.clear();
        for resource in &snapshot.resources {
            // Scope is a property of group + kind (it is identical across versions), so
            // keying without the version keeps lookups working during API upgrades.
            self.scopes.insert(
                (
                    resource.api_resource.group.clone(),
                    resource.api_resource.kind.clone(),
                ),
                resource.capabilities.scope.clone(),
            );
        }
    }

    fn scope_of(&self, gvk: &GroupVersionKind) -> Option<Scope> {
        self.scopes
            .get(&(gvk.group.clone(), gvk.kind.clone()))
            .cloned()
    }
}

/// TTL-bounded, single-flight API discovery cache.
#[derive(Clone)]
pub struct DiscoveryCache {
    state: Arc<RwLock<CachedDiscovery>>,
    index: Arc<StdRwLock<DiscoveryIndex>>,
    source: Arc<dyn DiscoverySource>,
    ttl: Duration,
    generation: Arc<AtomicU64>,
    refresh: Arc<Mutex<()>>,
}

impl std::fmt::Debug for DiscoveryCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiscoveryCache")
            .field("ttl", &self.ttl)
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl DiscoveryCache {
    /// Builds a cache backed by the live API server with [`DEFAULT_TTL`].
    #[must_use]
    pub fn new(client: kube::Client) -> Self {
        Self::with_source(Arc::new(KubeDiscoverySource::new(client)), DEFAULT_TTL)
    }

    /// Builds a cache over an arbitrary source and TTL.
    #[must_use]
    pub fn with_source(source: Arc<dyn DiscoverySource>, ttl: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(CachedDiscovery::empty())),
            index: Arc::new(StdRwLock::new(DiscoveryIndex::default())),
            source,
            ttl,
            generation: Arc::new(AtomicU64::new(0)),
            refresh: Arc::new(Mutex::new(())),
        }
    }

    /// The configured snapshot TTL.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Number of completed refreshes; used for observability and to assert coalescing.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Resolves a GVK from the cached snapshot.
    ///
    /// A fresh snapshot answers without any I/O. When the snapshot is stale, one coalesced
    /// refresh is tried (so concurrent callers still cost a single API-server round trip);
    /// if that refresh fails, a stale snapshot still answers a kind it already knows —
    /// graceful degradation keeps an active reconcile alive through a discovery outage —
    /// and otherwise the refresh error is surfaced. A miss on a *fresh* snapshot returns
    /// [`DiscoveryError::NoMatchesForKind`] without hammering the server. After installing
    /// a CRD, call [`DiscoveryCache::invalidate_and_refresh`] so the new kind resolves in
    /// the same sync (trap T6).
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::Refresh`] when the refresh itself fails and the stale snapshot
    /// cannot answer, or [`DiscoveryError::NoMatchesForKind`] when a fresh snapshot does
    /// not serve the kind.
    pub async fn resolve(
        &self,
        gvk: &GroupVersionKind,
    ) -> Result<(ApiResource, ApiCapabilities), DiscoveryError> {
        if self.is_stale().await
            && let Err(err) = self.ensure_fresh().await
        {
            return self.lookup(gvk).await.ok_or(err);
        }
        self.lookup(gvk)
            .await
            .ok_or_else(|| DiscoveryError::NoMatchesForKind {
                group: gvk.group.clone(),
                version: gvk.version.clone(),
                kind: gvk.kind.clone(),
            })
    }

    /// Refreshes only when the cached snapshot is older than the TTL.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::Refresh`] when the API server cannot be queried.
    pub async fn ensure_fresh(&self) -> Result<(), DiscoveryError> {
        let seen = self.generation();
        if !self.is_stale().await {
            return Ok(());
        }
        self.refresh_since(seen).await
    }

    /// Forces a refresh, coalesced with any other concurrent refresh.
    ///
    /// Call this after applying an in-bundle `CustomResourceDefinition` so the following
    /// CR resolves in the same sync (trap T6).
    ///
    /// # Errors
    ///
    /// [`DiscoveryError::Refresh`] when the API server cannot be queried.
    pub async fn invalidate_and_refresh(&self) -> Result<(), DiscoveryError> {
        let seen = self.generation();
        self.refresh_since(seen).await
    }

    /// Returns the API server `gitVersion` from the last successful refresh.
    ///
    /// Never blocks and never triggers a refresh: callers must have refreshed once
    /// (or called [`DiscoveryCache::resolve`]) before trusting the value.
    #[must_use]
    pub fn kube_version(&self) -> String {
        let version = read_recover(&self.index).kube_version.clone();
        if version.is_empty() {
            UNKNOWN_KUBE_VERSION.to_owned()
        } else {
            version
        }
    }

    async fn lookup(&self, gvk: &GroupVersionKind) -> Option<(ApiResource, ApiCapabilities)> {
        let state = self.state.read().await;
        state.resolve(gvk)
    }

    async fn is_stale(&self) -> bool {
        let state = self.state.read().await;
        state.is_stale(Instant::now(), self.ttl)
    }

    /// Single-flight refresh: only the first waiter for generation `seen` performs the
    /// API-server round trip; everyone else reuses its result.
    async fn refresh_since(&self, seen: u64) -> Result<(), DiscoveryError> {
        let _gate = self.refresh.lock().await;
        if self.generation() != seen {
            // Another task refreshed after our snapshot was taken.
            return Ok(());
        }

        let snapshot = self.source.fetch().await?;
        let fetched_at = Instant::now();
        {
            let mut state = self.state.write().await;
            state.replace(&snapshot, fetched_at);
        }
        {
            let mut index = write_recover(&self.index);
            index.replace(&snapshot);
        }
        // Published last: any task that observes the new generation is guaranteed to see
        // the refreshed snapshot when it looks it up.
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl ScopeLookup for DiscoveryCache {
    fn scope_of(&self, gvk: &GroupVersionKind) -> Option<Scope> {
        read_recover(&self.index).scope_of(gvk)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::{Mutex as StdMutex, PoisonError};

    use super::*;

    fn gvk(group: &str, version: &str, kind: &str) -> GroupVersionKind {
        GroupVersionKind::gvk(group, version, kind)
    }

    fn capabilities(scope: Scope) -> ApiCapabilities {
        ApiCapabilities {
            scope,
            subresources: Vec::new(),
            operations: vec!["get".to_owned()],
        }
    }

    /// Scripted discovery source recording how many round trips it served.
    #[derive(Debug, Default)]
    struct FakeSource {
        snapshot: StdMutex<DiscoverySnapshot>,
        fetches: AtomicU64,
        fail: AtomicBool,
    }

    impl FakeSource {
        fn with_snapshot(snapshot: DiscoverySnapshot) -> Self {
            Self {
                snapshot: StdMutex::new(snapshot),
                ..Self::default()
            }
        }

        fn with_configmap() -> Self {
            let snapshot = DiscoverySnapshot::new("v1.35.0").with_resource(
                ApiResource::from_gvk(&gvk("", "v1", "ConfigMap")),
                capabilities(Scope::Namespaced),
            );
            Self::with_snapshot(snapshot)
        }

        fn fetches(&self) -> u64 {
            self.fetches.load(Ordering::SeqCst)
        }

        fn set_kube_version(&self, version: &str) {
            let mut snapshot = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
            snapshot.kube_version = version.to_owned();
        }

        /// Simulates a `CustomResourceDefinition` being installed after the last snapshot.
        fn add_resource(&self, gvk: GroupVersionKind, scope: Scope) {
            let mut snapshot = self.snapshot.lock().unwrap_or_else(PoisonError::into_inner);
            snapshot.resources.push(DiscoveredResource {
                api_resource: ApiResource::from_gvk(&gvk),
                capabilities: capabilities(scope),
            });
        }
    }

    impl DiscoverySource for FakeSource {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                self.fetches.fetch_add(1, Ordering::SeqCst);
                if self.fail.load(Ordering::SeqCst) {
                    return Err(DiscoveryError::Refresh {
                        message: "apiserver unavailable".to_owned(),
                    });
                }
                let snapshot = self
                    .snapshot
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                Ok(snapshot)
            })
        }
    }

    #[test]
    fn staleness_is_ttl_bounded_and_empty_snapshots_are_always_stale() {
        let empty = CachedDiscovery::empty();
        let now = Instant::now();
        assert!(empty.is_stale(now, DEFAULT_TTL));
        assert!(empty.fetched_at().is_none());
        assert!(empty.is_empty());

        let mut cached = CachedDiscovery::empty();
        cached.replace(&DiscoverySnapshot::new("v1.35.0"), now);
        assert_eq!(cached.fetched_at(), Some(now));
        assert!(cached.is_empty());
        assert!(!cached.is_stale(now, DEFAULT_TTL));

        let four_minutes = now
            .checked_add(Duration::from_secs(240))
            .expect("instant arithmetic");
        let five_minutes = now
            .checked_add(Duration::from_secs(300))
            .expect("instant arithmetic");
        assert!(!cached.is_stale(four_minutes, DEFAULT_TTL));
        assert!(
            cached.is_stale(five_minutes, DEFAULT_TTL),
            "the TTL boundary must count as stale"
        );
        // A clock that moved backwards must not panic.
        let earlier = now
            .checked_sub(Duration::from_secs(60))
            .expect("instant arithmetic");
        assert!(!cached.is_stale(earlier, DEFAULT_TTL));
    }

    #[tokio::test]
    async fn resolve_hits_the_cache_without_refreshing() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), DEFAULT_TTL);

        for _ in 0..3 {
            let (api_resource, caps) = cache
                .resolve(&gvk("", "v1", "ConfigMap"))
                .await
                .expect("configmap resolves");
            assert_eq!(api_resource.kind, "ConfigMap");
            assert_eq!(caps.scope, Scope::Namespaced);
        }
        assert_eq!(source.fetches(), 1, "repeat resolves must not refetch");
        assert_eq!(cache.generation(), 1);
    }

    #[tokio::test]
    async fn every_served_version_of_a_kind_resolves() {
        // Built through `append_all_versions`, i.e. exactly how `KubeDiscoverySource::fetch`
        // now assembles a snapshot: a CRD serving both `example.com/v1` and
        // `example.com/v1alpha1` yields one entry per version. With the previous
        // `resources_by_stability()` snapshot only `v1` would be present, so the
        // `v1alpha1` resolve below would fail with `NoMatchesForKind`.
        let mut snapshot = DiscoverySnapshot::new("v1.35.0");
        append_all_versions(&mut snapshot, ["v1", "v1alpha1"], |version| {
            vec![(
                ApiResource::from_gvk(&gvk("example.com", version, "Widget")),
                capabilities(Scope::Namespaced),
            )]
        });
        assert_eq!(
            snapshot.resources.len(),
            2,
            "one entry per served group/version/kind"
        );

        let source = Arc::new(FakeSource::with_snapshot(snapshot));
        let cache = DiscoveryCache::with_source(source.clone(), DEFAULT_TTL);

        for version in ["v1", "v1alpha1"] {
            let gvk = gvk("example.com", version, "Widget");
            let (api_resource, caps) = cache.resolve(&gvk).await.expect("both versions resolve");
            assert_eq!(api_resource.version, version);
            assert_eq!(api_resource.api_version, format!("example.com/{version}"));
            assert_eq!(api_resource.kind, "Widget");
            assert_eq!(caps.scope, Scope::Namespaced);

            // Scope is keyed on group + kind, so every version reports the same scope.
            assert_eq!(cache.scope_of(&gvk), Some(Scope::Namespaced));
        }
        assert_eq!(source.fetches(), 1, "one snapshot serves every version");

        // A version the API server genuinely does not serve still reports a miss, which
        // cleanup treats as already deleted and apply as terminal.
        let absent = gvk("example.com", "v2", "Widget");
        let err = cache.resolve(&absent).await.expect_err("v2 is not served");
        assert!(err.is_no_matches_for_kind(), "{err}");
    }

    #[tokio::test]
    async fn concurrent_misses_are_coalesced_into_a_single_refresh() {
        const TASKS: usize = 8;

        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), DEFAULT_TTL);
        let barrier = Arc::new(tokio::sync::Barrier::new(TASKS));

        let mut handles = Vec::with_capacity(TASKS);
        for _ in 0..TASKS {
            let cache = cache.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                cache.resolve(&gvk("", "v1", "ConfigMap")).await
            }));
        }
        for handle in handles {
            let resolved = handle.await.expect("resolve task must not panic");
            assert!(resolved.is_ok(), "every waiter must see the snapshot");
        }

        assert_eq!(
            source.fetches(),
            1,
            "{TASKS} concurrent misses must trigger exactly one discovery round trip"
        );
        assert_eq!(cache.generation(), 1);
    }

    #[tokio::test]
    async fn ensure_fresh_refreshes_only_after_the_ttl() {
        let source = Arc::new(FakeSource::with_configmap());
        let forever = DiscoveryCache::with_source(source.clone(), Duration::from_secs(3600));
        forever.ensure_fresh().await.expect("first refresh");
        forever.ensure_fresh().await.expect("cached refresh");
        assert_eq!(source.fetches(), 1, "a fresh snapshot must not refetch");

        let expire_immediately = DiscoveryCache::with_source(source.clone(), Duration::ZERO);
        expire_immediately.ensure_fresh().await.expect("refresh");
        expire_immediately.ensure_fresh().await.expect("refresh");
        assert_eq!(
            source.fetches(),
            3,
            "a zero TTL must refresh on every call (2 for this cache + 1 above)"
        );
    }

    #[tokio::test]
    async fn invalidate_and_refresh_bypasses_the_ttl_and_updates_the_kube_version() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), Duration::from_secs(3600));

        assert_eq!(cache.kube_version(), UNKNOWN_KUBE_VERSION);
        cache.ensure_fresh().await.expect("initial refresh");
        assert_eq!(cache.kube_version(), "v1.35.0");
        assert_eq!(source.fetches(), 1);

        // A brand-new CRD appears in the API server after the last fetch.
        source.set_kube_version("v1.35.1");
        cache
            .invalidate_and_refresh()
            .await
            .expect("forced refresh");
        assert_eq!(source.fetches(), 2, "invalidation must force a refresh");
        assert_eq!(cache.kube_version(), "v1.35.1");
    }

    #[tokio::test]
    async fn forced_refresh_makes_a_newly_installed_crd_resolvable() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), Duration::from_secs(3600));
        cache.ensure_fresh().await.expect("initial refresh");

        let widget = gvk("example.com", "v1", "Widget");
        assert!(
            cache
                .resolve(&widget)
                .await
                .expect_err("not in the snapshot yet")
                .is_no_matches_for_kind()
        );
        assert_eq!(
            source.fetches(),
            1,
            "a fresh miss must not hammer discovery"
        );

        // CRD + CR in one sync: install the CRD, invalidate, then resolve the CR.
        source.add_resource(widget.clone(), Scope::Namespaced);
        cache
            .invalidate_and_refresh()
            .await
            .expect("forced refresh");

        let (_, capabilities) = cache.resolve(&widget).await.expect("new CRD resolves");
        assert_eq!(capabilities.scope, Scope::Namespaced);
        assert_eq!(
            cache.scope_of(&gvk("example.com", "v9", "Widget")),
            Some(Scope::Namespaced),
            "the synchronous scope index must be rebuilt without a version key"
        );
        assert_eq!(source.fetches(), 2);
    }

    #[tokio::test]
    async fn concurrent_invalidations_are_coalesced() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), Duration::from_secs(3600));

        let first = cache.clone();
        let second = cache.clone();
        let (one, two) = tokio::join!(
            async move { first.invalidate_and_refresh().await },
            async move { second.invalidate_and_refresh().await }
        );
        one.expect("first invalidation");
        two.expect("second invalidation");
        assert_eq!(source.fetches(), 1, "concurrent invalidations coalesce");
    }

    #[tokio::test]
    async fn unknown_kinds_report_no_matches_for_kind() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), DEFAULT_TTL);

        let err = cache
            .resolve(&gvk("apps", "v1", "Deployment"))
            .await
            .expect_err("deployment is not served by the fake");
        assert!(err.is_no_matches_for_kind(), "{err}");
        assert!(matches!(
            err,
            DiscoveryError::NoMatchesForKind {
                ref group,
                ref version,
                ref kind,
            } if group == "apps" && version == "v1" && kind == "Deployment"
        ));
        let text = err.to_string();
        assert!(
            text.contains("Deployment") && text.contains("apps"),
            "{text}"
        );
    }

    #[tokio::test]
    async fn refresh_failures_are_surfaced_without_corrupting_the_cache() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), Duration::ZERO);

        cache
            .resolve(&gvk("", "v1", "ConfigMap"))
            .await
            .expect("warm");
        let warm = cache.generation();

        source.fail.store(true, Ordering::SeqCst);
        let err = cache
            .invalidate_and_refresh()
            .await
            .expect_err("refresh must fail");
        assert!(matches!(err, DiscoveryError::Refresh { .. }), "{err}");
        assert_eq!(
            cache.generation(),
            warm,
            "a failed refresh must not publish a new generation"
        );

        // The previously cached snapshot is still resolvable (graceful degradation: a
        // stale-but-known kind keeps answering through a discovery outage).
        let (api_resource, _) = cache
            .resolve(&gvk("", "v1", "ConfigMap"))
            .await
            .expect("cached snapshot survives a failed refresh");
        assert_eq!(api_resource.version, "v1");
        assert_eq!(cache.kube_version(), "v1.35.0");

        // A stale snapshot that cannot answer must surface the refresh error, not
        // masquerade as `NoMatchesForKind`.
        let err = cache
            .resolve(&gvk("apps", "v1", "Deployment"))
            .await
            .expect_err("an unknown kind under a failed refresh must fail");
        assert!(
            matches!(err, DiscoveryError::Refresh { .. }),
            "the refresh error must win over NoMatchesForKind: {err}"
        );
        assert!(!err.is_no_matches_for_kind());
        assert_eq!(
            cache.generation(),
            warm,
            "failed resolves must never publish a generation"
        );
    }

    #[tokio::test]
    async fn a_fresh_snapshot_miss_returns_no_matches_without_refreshing() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), Duration::from_secs(3600));
        cache.ensure_fresh().await.expect("initial refresh");
        assert_eq!(source.fetches(), 1);

        for _ in 0..3 {
            let err = cache
                .resolve(&gvk("apps", "v1", "Deployment"))
                .await
                .expect_err("the fake does not serve deployments");
            assert!(err.is_no_matches_for_kind(), "{err}");
        }
        assert_eq!(
            source.fetches(),
            1,
            "a miss on a fresh snapshot must not hammer discovery"
        );
    }

    #[tokio::test]
    async fn scope_lookup_indexes_group_and_kind_without_a_version() {
        let source = Arc::new(FakeSource::with_configmap());
        let cache = DiscoveryCache::with_source(source.clone(), DEFAULT_TTL);
        assert_eq!(cache.scope_of(&gvk("", "v1", "ConfigMap")), None);

        cache.ensure_fresh().await.expect("refresh");
        assert_eq!(
            cache.scope_of(&gvk("", "v1", "ConfigMap")),
            Some(Scope::Namespaced)
        );
        // Scope is version-independent: an API upgrade must not lose it.
        assert_eq!(
            cache.scope_of(&gvk("", "v2", "ConfigMap")),
            Some(Scope::Namespaced)
        );
        assert_eq!(cache.scope_of(&gvk("apps", "v1", "Deployment")), None);
    }
}
