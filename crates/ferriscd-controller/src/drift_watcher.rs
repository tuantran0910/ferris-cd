//! Opt-in, label-scoped `PartialObjectMetadata` drift watcher (`T18.2`).
//!
//! Under Model 1 (ADR-004) an out-of-band `kubectl edit` / `kubectl delete` waits up to
//! `spec.requeueAfterSeconds` (default `180s`) before FerrisCD notices it. This module adds an
//! **opt-in trigger source**: a metadata-only watch of the kinds the fleet actually owns, which
//! enqueues a reconcile as soon as something outside FerrisCD touches one of our objects.
//!
//! # The shape of the thing
//!
//! ```text
//! Application.status.inventory ──► plan_watch_requests ──► (cluster, GVK) up to 64 per cluster
//!                                                             │
//!                          ClusterManager::subscribe() ─────────┤ start/cancel on Added/Rebuilt/Removed
//!                                                             ▼
//!   metadata_watcher(Api::<PartialObjectMeta<DynamicObject>>::all_with(..),
//!                    Config::default().labels("ferriscd.io/managed-by=ferriscd"))
//!                                                             │  metadata only: no .spec/.status/Secret.data
//!                                                             ▼
//!   DriftRouter: SelfEchoCache ──► app-hash lookup ──► Sharding filter ──► 2s/5s trailing debounce
//!                                                             │
//!                                                             ▼  try_send (never blocks)
//!   mpsc::channel(256) per NamespacedController ──► Controller::reconcile_on(..)
//! ```
//!
//! # Why metadata only, and why the label selector is not optional
//!
//! `metadata_watcher` asks the API server for `application/json;as=PartialObjectMetadata`, so the
//! response carries `metadata` and nothing else: no `.spec`, no `.status`, and therefore **no
//! `Secret.data`** byte ever crosses the wire or reaches this process (trap guard). The
//! `ferriscd.io/managed-by=ferriscd` selector (`T18.1`) is what keeps the watch from streaming every
//! object in the cluster: the API server filters, this process never sees a foreign object.
//!
//! # The `SelfEchoCache` is what stops the feedback loop
//!
//! FerrisCD's own Server-Side Apply produces a watch event. For a generation-bearing kind
//! (`Deployment`, `Service`, …) the echo is invisible — the controller ignores an event whose
//! `(uid, generation)` it already recorded. For a **generation-less** kind (`ConfigMap`, `Secret`)
//! there is no generation to compare, so without [`SelfEchoCache`] every apply would trigger the
//! reconcile that applies again: an infinite apply/watch loop. The cache therefore records the
//! `metadata.resource_version` of every apply (and a marker for every confirmed prune) and drops the
//! event that matches it. It is bounded ([`SELF_ECHO_CAPACITY`]) and TTL-expiring
//! ([`SELF_ECHO_TTL`]), so a stale entry can only ever cost one extra reconcile, never a missed
//! drift (see [`SelfEchoCache::suppresses`] for the exact contract, including an out-of-order echo).
//!
//! # Failure is a fallback, not an outage
//!
//! `403`/`404`/`405` mean the watch will never succeed in this configuration (RBAC does not allow
//! it, the kind is gone, or the endpoint does not serve `watch`). The watcher logs one structured
//! `warn!`, increments `ferriscd_drift_watcher_fallback_total{reason}`, parks on a
//! [`FALLBACK_COOLDOWN`] window and leaves the `Application`s alone: Model 1 polling is *still*
//! running, so drift is still detected, just not in sub-second time. Nothing is marked
//! `Ready=False` and nothing panics.
//!
//! # What is deliberately not here
//!
//! * No cluster-wide informer of whole objects: the ceiling is [`MAX_DRIFT_WATCHES`] metadata
//!   watches per cluster, derived strictly from `status.inventory`.
//! * No object cache: an event is reduced to a handful of `String`s ([`ObservedResource`]), used for
//!   a hash lookup, and dropped.
//! * No blocking send: the trigger channel is fed with `try_send` only, so a slow (or full)
//!   controller queue can never stall a watch stream.
//!
//! # Deviation from the roadmap wording: `metadata_watcher` is deprecated in `kube 5.1`
//!
//! `T18.2` says "use `kube::runtime::watcher::metadata_watcher`". In `kube 5.1` that helper is
//! **deprecated**: it still works, but it is a thin wrapper that builds exactly the `Api` below.
//! The supported spelling is `Api::<PartialObjectMeta<DynamicObject>>::all_with(client,
//! &api_resource)` (whose `Resource::metadata_api()` is `true`, so every request carries
//! `Accept: application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1`) plus the ordinary
//! [`watcher::watcher`]. This module does that, for two reasons that matter here:
//!
//! * the same call path can be pinned at the wire (see
//!   `the_metadata_watch_asks_for_metadata_only_and_is_label_scoped`), which a deprecated wrapper
//!   with its own `PartialObjectMeta` layer cannot be;
//! * `metadata_watcher`'s extra layer only re-shapes the item type — it adds no metadata-only
//!   guarantee, so using it would keep the deprecated API without buying anything.
//!
//! The observable contract is unchanged: metadata only, one server-side label selector, nothing
//! retained.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferriscd_crd::Application;
use ferriscd_crd::annotations;
use ferriscd_crd::status::InventoryEntry as StatusInventoryEntry;
use ferriscd_engine::inventory::from_status_entries;
use ferriscd_engine::manifest::ResourceKey;
use futures::future::BoxFuture;
use futures::{Stream, StreamExt};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::ResourceExt;
use kube::api::{ApiResource, DynamicObject};
use kube::core::{GroupVersionKind, PartialObjectMeta};
use kube::runtime::reflector::{self, Store};
use kube::runtime::watcher;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::cluster_manager::{ClusterLifecycleEvent, ClusterManager, IN_CLUSTER};
use crate::metrics::{DriftFallbackReason, DriftWatchOutcome, Metrics};
use crate::sharding::Sharding;
use crate::{lock_recover, read_recover, write_recover};

/// Hard ceiling on concurrent metadata watches **per cluster**.
///
/// Every watch is a separate `list+watch` request against the API server, and an unbounded set
/// would eventually exhaust its watch budget. The plan is derived from the fleet's
/// `status.inventory`, so a large fleet can exceed this; the excess is dropped deterministically
/// (sorted by `group/kind`) and logged once per refresh instead of failing anything.
pub const MAX_DRIFT_WATCHES: usize = 64;

/// Capacity of the per-scope drift-trigger channel.
///
/// Bounded on purpose: a controller whose queue is saturated drops the trigger and the next
/// periodic reconcile (Model 1) still converges the `Application`, so back-pressure here can only
/// cost latency, never correctness.
pub const DRIFT_TRIGGER_CAPACITY: usize = 256;

/// Trailing debounce window applied per `Application`.
pub const DRIFT_DEBOUNCE: Duration = Duration::from_secs(2);

/// Ceiling on the trailing debounce: a continuously noisy object still triggers this often.
pub const DRIFT_MAX_DEBOUNCE: Duration = Duration::from_secs(5);

/// How long a `SelfEchoCache` entry suppresses an echo of FerrisCD's own write.
pub const SELF_ECHO_TTL: Duration = Duration::from_secs(60);

/// Hard cap on `SelfEchoCache` entries (LRU-by-recency eviction beyond it).
pub const SELF_ECHO_CAPACITY: usize = 10_000;

/// How many writes may pass between two full `SelfEchoCache` sweeps.
///
/// The sweep only reclaims *expired* entries and trims the cache to its cap; it is never needed
/// for correctness (a lookup checks the TTL of the key it observes). Amortizing it over a few
/// hundred writes keeps recording `O(1)` for a large fleet while still bounding the memory of a
/// long-lived process to the cap plus one sweep interval of writes.
pub const SWEEP_INTERVAL: usize = 256;

/// How long a watcher parks after a permanent (`403`/`404`/`405`) failure.
pub const FALLBACK_COOLDOWN: Duration = Duration::from_secs(15 * 60);

/// How often the active watch set is recomputed from the `Application` stores.
///
/// Cluster lifecycle events trigger the same recomputation immediately; this tick only picks up
/// inventory changes (a new GVK entering `status.inventory`).
pub const WATCH_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Pause before rebuilding a watch whose stream ended without an error.
///
/// `kube`'s watcher already reconnects with its own backoff, so this only covers the case where the
/// stream itself was dropped. It is short on purpose: a dead watch must not linger, and a rebuild is
/// cheap (one `list+watch` of metadata).
pub const ENDED_RESTART_DELAY: Duration = Duration::from_secs(5);

/// Environment variable carrying the optional kind allow-list.
pub const DRIFT_WATCHER_KINDS_ENV: &str = "FERRISCD_DRIFT_WATCHER_KINDS";

/// The server-side label selector every drift watch uses.
///
/// `ferriscd.io/managed-by=ferriscd` is stamped by `T18.1`; selecting on it is what keeps the watch
/// from carrying foreign objects. Annotations cannot be selected on, which is why `T18.1` added a
/// label at all.
#[must_use]
pub fn label_selector() -> String {
    format!(
        "{}={}",
        annotations::LABEL_MANAGED_BY,
        annotations::MANAGED_BY_FERRISCD
    )
}

/// Misconfiguration of the opt-in drift watcher.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DriftConfigError {
    /// An entry of `--drift-watcher-kinds` was blank.
    #[error(
        "`--drift-watcher-kinds` contains an empty entry; use a comma-separated list of \
         `Kind` or `group/Kind` values, or omit the flag to watch every inventory kind"
    )]
    EmptyKindEntry,

    /// An entry of `--drift-watcher-kinds` was not `Kind` or `group/Kind`.
    #[error(
        "`--drift-watcher-kinds` entry {entry:?} is not `Kind` or `group/Kind`; a blank kind or \
         more than one `/` cannot match an inventory key"
    )]
    InvalidKindEntry {
        /// The offending entry, verbatim.
        entry: String,
    },
}

/// `group` + `kind` of one watched resource type (never the version: identity is GKNN).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupKind {
    /// API group (empty for the core group).
    pub group: String,
    /// Resource kind (PascalCase, e.g. `ConfigMap`).
    pub kind: String,
}

impl GroupKind {
    /// Builds a `group`/`kind` pair.
    #[must_use]
    pub fn new(group: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            group: group.into(),
            kind: kind.into(),
        }
    }

    /// Stable `<group>/<kind>` label for logs.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}/{}", self.group, self.kind)
    }
}

/// One entry of the `--drift-watcher-kinds` allow-list.
///
/// `group: None` is the bare `Kind` spelling and matches the kind in **any** group; `group:
/// Some("")` is the `/Kind` spelling and matches the core group only. Keeping the wildcard as
/// `None` (rather than an empty group string) is what stops `Kind` and `/Kind` from collapsing into
/// the same rule.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KindSelector {
    /// API group, or `None` for "any group".
    pub group: Option<String>,
    /// Resource kind (exact, case-sensitive: Kinds are PascalCase by convention).
    pub kind: String,
}

impl KindSelector {
    /// The spelling this selector accepts, for logs.
    #[must_use]
    pub fn label(&self) -> String {
        match &self.group {
            Some(group) => format!("{group}/{}", self.kind),
            None => self.kind.clone(),
        }
    }
}

/// The `--drift-watcher-kinds` allow-list.
///
/// The default ([`Self::All`]) watches every kind in `status.inventory`, which is what the roadmap
/// asks for. Restricting it is an operator lever for a cluster whose API server cannot afford 64
/// watches: only the listed kinds are watched, everything else falls back to Model 1 polling.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum DriftKindFilter {
    /// Watch every kind an `Application` reports in `status.inventory` (the default).
    #[default]
    All,
    /// Watch only these kinds.
    Only(BTreeSet<KindSelector>),
}

impl DriftKindFilter {
    /// Parses a comma-separated `Kind` / `group/Kind` list.
    ///
    /// `None` or a blank value means [`Self::All`]. Parsing is deliberately literal (no wildcards,
    /// no trimming inside a segment): a typo must not silently watch the wrong kinds, and
    /// `Kind` matches that kind in **any** group while `group/Kind` matches exactly.
    ///
    /// # Errors
    ///
    /// [`DriftConfigError::EmptyKindEntry`] for a blank entry (e.g. `a,,b`) and
    /// [`DriftConfigError::InvalidKindEntry`] for anything that is not `Kind` or `group/Kind`.
    pub fn parse(value: Option<&str>) -> Result<Self, DriftConfigError> {
        let Some(value) = value else {
            return Ok(Self::All);
        };
        if value.trim().is_empty() {
            return Ok(Self::All);
        }
        let mut kinds = BTreeSet::new();
        for raw in value.split(',') {
            let entry = raw.trim();
            if entry.is_empty() {
                return Err(DriftConfigError::EmptyKindEntry);
            }
            let mut segments = entry.split('/');
            let parsed = match (segments.next(), segments.next(), segments.next()) {
                (Some(kind), None, None) if !kind.is_empty() => KindSelector {
                    group: None,
                    kind: kind.to_owned(),
                },
                (Some(group), Some(kind), None) if !kind.is_empty() => KindSelector {
                    group: Some(group.to_owned()),
                    kind: kind.to_owned(),
                },
                _ => {
                    return Err(DriftConfigError::InvalidKindEntry {
                        entry: entry.to_owned(),
                    });
                }
            };
            kinds.insert(parsed);
        }
        Ok(Self::Only(kinds))
    }

    /// Whether a `group`/`kind` may be watched.
    #[must_use]
    pub fn allows(&self, group: &str, kind: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(kinds) => kinds.iter().any(|selector| {
                selector.kind == kind
                    && selector
                        .group
                        .as_deref()
                        .is_none_or(|selected| selected == group)
            }),
        }
    }

    /// The parsed allow-list, or `None` for [`Self::All`] (for logging).
    #[must_use]
    pub fn kinds(&self) -> Option<Vec<String>> {
        match self {
            Self::All => None,
            Self::Only(kinds) => Some(kinds.iter().map(KindSelector::label).collect()),
        }
    }
}

/// Tuning for the opt-in drift watcher.
///
/// `Default` is **disabled**, so nothing about a `v1.0` deployment changes until an operator passes
/// `--enable-drift-watcher` (`FERRISCD_ENABLE_DRIFT_WATCHER`). Every window is a field rather than a
/// constant so the unit tests can drive the state machine with an injected clock and no real waits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriftWatcherConfig {
    /// Whether the watcher (and the `T18.1` label stamping that feeds it) is on.
    pub enabled: bool,
    /// Which `group`/`kind` pairs may be watched.
    pub kinds: DriftKindFilter,
    /// Ceiling on concurrent watches per cluster ([`MAX_DRIFT_WATCHES`]).
    pub max_watches: usize,
    /// Per-`Application` trailing debounce ([`DRIFT_DEBOUNCE`]).
    pub debounce: Duration,
    /// Trailing-debounce ceiling ([`DRIFT_MAX_DEBOUNCE`]).
    pub max_debounce: Duration,
    /// `SelfEchoCache` TTL ([`SELF_ECHO_TTL`]).
    pub echo_ttl: Duration,
    /// `SelfEchoCache` entry cap ([`SELF_ECHO_CAPACITY`]).
    pub echo_capacity: usize,
    /// Cooldown after a permanent watch failure ([`FALLBACK_COOLDOWN`]).
    pub fallback_cooldown: Duration,
    /// Capacity of each per-scope trigger channel ([`DRIFT_TRIGGER_CAPACITY`]).
    pub trigger_capacity: usize,
}

impl Default for DriftWatcherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            kinds: DriftKindFilter::All,
            max_watches: MAX_DRIFT_WATCHES,
            debounce: DRIFT_DEBOUNCE,
            max_debounce: DRIFT_MAX_DEBOUNCE,
            echo_ttl: SELF_ECHO_TTL,
            echo_capacity: SELF_ECHO_CAPACITY,
            fallback_cooldown: FALLBACK_COOLDOWN,
            trigger_capacity: DRIFT_TRIGGER_CAPACITY,
        }
    }
}

impl DriftWatcherConfig {
    /// The shipped default: disabled.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Maps `--enable-drift-watcher` onto the configuration.
    #[must_use]
    pub fn from_flag(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    /// Restricts the watched kinds (builder style).
    #[must_use]
    pub fn with_kinds(mut self, kinds: DriftKindFilter) -> Self {
        self.kinds = kinds;
        self
    }

    /// Overrides the per-cluster watch ceiling (builder style, clamped to at least `1`).
    #[must_use]
    pub fn with_max_watches(mut self, max_watches: usize) -> Self {
        self.max_watches = max_watches.max(1);
        self
    }

    /// Overrides the debounce windows (builder style).
    #[must_use]
    pub fn with_debounce(mut self, debounce: Duration, max_debounce: Duration) -> Self {
        self.debounce = debounce;
        self.max_debounce = max_debounce.max(debounce);
        self
    }

    /// Overrides the `SelfEchoCache` bounds (builder style).
    #[must_use]
    pub fn with_echo(mut self, ttl: Duration, capacity: usize) -> Self {
        self.echo_ttl = ttl;
        self.echo_capacity = capacity.max(1);
        self
    }

    /// Overrides the fallback cooldown (builder style).
    #[must_use]
    pub fn with_fallback_cooldown(mut self, cooldown: Duration) -> Self {
        self.fallback_cooldown = cooldown;
        self
    }

    /// Overrides the trigger-channel capacity (builder style, clamped to at least `1`).
    ///
    /// `tokio::sync::mpsc::channel` panics on a zero capacity, so the clamp is what makes a
    /// misconfigured value a bounded channel instead of a startup panic.
    #[must_use]
    pub fn with_trigger_capacity(mut self, capacity: usize) -> Self {
        self.trigger_capacity = capacity.max(1);
        self
    }

    /// A `SelfEchoCache` for this configuration.
    #[must_use]
    pub fn echo_cache(&self) -> SelfEchoCache {
        SelfEchoCache::new(self.echo_ttl, self.echo_capacity)
    }
}

/// One recorded observation of a managed object's **metadata** (never its body).
///
/// Deliberately borrowed and `Copy`: the classifier never owns an object, so nothing in this
/// module can accidentally retain (or log) a full resource.
#[derive(Clone, Copy, Debug)]
pub struct MetadataObservation<'a> {
    /// The cluster the event came from (`in-cluster`, or a registered remote).
    ///
    /// Part of the echo identity (finding M-1): two clusters can hold the *same* GKNN, and a write
    /// FerrisCD made in one of them says nothing about an event in the other.
    pub cluster: &'a str,
    /// Version-agnostic identity of the observed object.
    pub key: &'a ResourceKey,
    /// `metadata.uid`, if the API server reported one.
    pub uid: Option<&'a str>,
    /// `metadata.generation`, present only for generation-bearing kinds.
    pub generation: Option<i64>,
    /// `metadata.resourceVersion`.
    pub resource_version: Option<&'a str>,
    /// Whether this observation is a `Delete` event (rather than an apply/update).
    pub deleted: bool,
}

/// Why an event was recognised as FerrisCD's own write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfEcho {
    /// The object did not change since FerrisCD wrote it (`ConfigMap`/`Secret`).
    Write,
    /// The object's `(uid, generation)` is exactly what FerrisCD last applied, so only `/status`
    /// moved (or nothing did).
    UnchangedGeneration,
    /// FerrisCD pruned the object itself.
    Prune,
}

impl SelfEcho {
    /// Stable label for logs and metrics.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "self_echo",
            Self::UnchangedGeneration => "unchanged_generation",
            Self::Prune => "self_pruned",
        }
    }
}

/// What FerrisCD last wrote for one managed object.
#[derive(Clone, Debug, PartialEq, Eq)]
struct EchoEntry {
    uid: Option<String>,
    generation: Option<i64>,
    resource_version: Option<String>,
    pruned: bool,
    recorded_at: Instant,
}

/// The identity of one recorded echo: **the destination cluster and the object's GKNN**.
///
/// The cluster is part of the key (finding M-1): `ResourceKey` is version-agnostic and
/// cluster-agnostic, so without it a prune marker recorded while pruning `team-a/settings` in
/// cluster A would suppress the `Delete` of `team-a/settings` in cluster B within the TTL — hiding a
/// real out-of-band delete in a cluster FerrisCD never touched.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct EchoKey {
    cluster: String,
    resource: ResourceKey,
}

impl EchoKey {
    /// Builds the key of one observation/record call.
    ///
    /// The cluster is **trimmed** here, which is the single choke point that makes the record side
    /// (`SyncExecutor` passes the raw `spec.destination.cluster`) and the lookup side
    /// (`ObservedResource.cluster`, which comes from a plan that is already trimmed) use the same
    /// identity. Without it a padded `"  in-cluster  "` would record an echo under one spelling and
    /// look it up under another, so the generation-less apply/watch feedback loop the cache exists to
    /// break would reopen for exactly those `Application`s.
    fn new(cluster: &str, resource: &ResourceKey) -> Self {
        Self {
            cluster: cluster.trim().to_owned(),
            resource: resource.clone(),
        }
    }
}

/// Bounded, TTL-expiring memory of FerrisCD's own writes.
///
/// # What it suppresses
///
/// * **Generation-bearing kinds** (the event carries `metadata.generation`): an event whose
///   `(uid, generation)` equals the recorded pair is ignored. That is the `Deployment`/`Service`
///   case: a `kubectl edit` bumps `generation` and triggers, while a `/status`-only write or the
///   echo of our own apply does not. A match also refreshes the entry's `recorded_at`, so a
///   long-lived object that only churns `/status` never loses its baseline to the TTL.
/// * **Generation-less kinds** (`ConfigMap`, `Secret`): an event whose `resource_version` equals the
///   recorded one is ignored — that is the only thing that breaks the apply/watch feedback loop.
/// * **`Delete` events**: ignored **only** when a prune marker proves FerrisCD issued the delete,
///   and only **once** (see below).
///
/// # Why a `Delete` needs the marker, and not a resource version
///
/// A `Delete` event carries the object's *last written* `resourceVersion`, so the version of an
/// object FerrisCD just applied is indistinguishable from the version of the same object deleted
/// externally a moment later. Suppressing on that match would hide an out-of-band
/// `kubectl delete` **forever** — the object is gone, so no later event can correct the mistake.
/// Only [`SelfEchoCache::record_prune`] (recorded by every delete FerrisCD itself issues) is
/// evidence, and a matching version without a marker therefore triggers.
///
/// # Why a marker is one-shot (finding M-2)
///
/// A marker is consumed by the event it suppresses: the moment it does its job it is removed, so it
/// can never suppress a *second* `Delete` for the same key. One object is created, deleted and
/// re-created within the TTL all the time (a `Replace`, a prune followed by a re-add to Git), and a
/// durable marker would silently absorb the external delete that follows — the one event the
/// marker exists to be distinguished from.
///
/// One-shot is not the same as *consumed promptly* (finding M-2 residual): a marker whose own
/// `Delete` never arrives — the object was already gone (`AlreadyGone`), the watch was down when the
/// event happened, or the event was dropped — simply sits until the TTL expires, and during that
/// remaining window it can suppress **one** external `Delete` of that key (for instance the delete
/// half of an external create+delete). The window is bounded by [`SELF_ECHO_TTL`] (60 s) and Model 1
/// periodic polling converges the `Application` regardless, so the worst case is one delayed
/// self-heal, never a permanently hidden drift.
///
/// # What it deliberately does *not* suppress
///
/// An entry older than the TTL is treated as absent **and evicted** (the clock is the caller's, so
/// this is deterministic in tests): a stale record can cost one extra reconcile, never a missed
/// drift. An event whose `resource_version` is not the recorded one is treated as external even if
/// it is *older* (an out-of-order echo): resource versions are opaque, so equality is the only
/// sound comparison, and the error is biased towards one harmless no-op reconcile rather than
/// towards silently ignoring a real edit.
///
/// # Cost
///
/// Recording is `O(1)` amortized: entries are only swept when the cache is at (or over) its
/// capacity, or once every [`SWEEP_INTERVAL`] writes, so a busy fleet does not pay an `O(n)` pass
/// per write and a full cache is trimmed in one sorted pass instead of an `O(n²)` scan per eviction.
pub struct SelfEchoCache {
    entries: Mutex<EchoEntries>,
    ttl: Duration,
    capacity: usize,
}

/// The cache's mutable state: the map plus the amortization counter.
#[derive(Debug, Default)]
struct EchoEntries {
    entries: HashMap<EchoKey, EchoEntry>,
    writes_since_sweep: usize,
}

impl std::fmt::Debug for SelfEchoCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfEchoCache")
            .field("entries", &self.len())
            .field("capacity", &self.capacity)
            .field("ttl", &self.ttl)
            .finish()
    }
}

impl SelfEchoCache {
    /// Builds a cache with a TTL and an entry cap (both clamped to "at least one second / entry").
    #[must_use]
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            entries: Mutex::new(EchoEntries::default()),
            ttl,
            capacity: capacity.max(1),
        }
    }

    /// Builds a cache with the roadmap defaults ([`SELF_ECHO_TTL`], [`SELF_ECHO_CAPACITY`]).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SELF_ECHO_TTL, SELF_ECHO_CAPACITY)
    }

    /// How many entries are held (expired ones included until the next sweep).
    #[must_use]
    pub fn len(&self) -> usize {
        lock_recover(&self.entries).entries.len()
    }

    /// Whether nothing has been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Records the object the API server returned from a Server-Side Apply.
    ///
    /// `cluster` is the **destination** cluster the write went to (`spec.destination.cluster`), and
    /// is part of the entry's identity (finding M-1).
    pub fn record_apply(
        &self,
        cluster: &str,
        key: &ResourceKey,
        metadata: &ObjectMeta,
        now: Instant,
    ) {
        self.record_metadata(cluster, key, metadata, now);
    }

    /// Seeds the baseline of one object observed during a watch's initial list.
    ///
    /// A re-list is **not** evidence of drift: the objects it delivers are the state the cluster is
    /// in, and treating each one as a change would trigger a reconcile storm on every reconnect (and
    /// on every `410 Gone` recovery). Seeding through the same cache also gives a generation-bearing
    /// kind a baseline, so the first `/status`-only event after a reconnect is filtered exactly like
    /// a steady-state one. Drift that happened *while* the watch was down is Model 1's job.
    pub fn record_baseline(
        &self,
        cluster: &str,
        key: &ResourceKey,
        metadata: &ObjectMeta,
        now: Instant,
    ) {
        self.record_metadata(cluster, key, metadata, now);
    }

    /// Records a **confirmed prune** of `key` in `cluster`, i.e. a delete FerrisCD issued itself.
    ///
    /// This marker is the *only* thing that suppresses a `Delete` watch event: the event carries the
    /// object's last written resource version, which cannot distinguish "we deleted what we wrote"
    /// from "somebody deleted it after we wrote it" (finding C1). Callers therefore record it on
    /// every delete FerrisCD issues — `Pruner::prune` and `Replace=true` (which deletes before it
    /// re-applies), both including a delete the API server answered with `404`/`410`
    /// (`AlreadyGone`: FerrisCD did issue that delete, it just found nothing left to remove) — and
    /// never on a delete FerrisCD did not attempt.
    ///
    /// The marker suppresses exactly **one** event (finding M-2): see the type documentation.
    pub fn record_prune(&self, cluster: &str, key: &ResourceKey, now: Instant) {
        self.insert(
            EchoKey::new(cluster, key),
            EchoEntry {
                uid: None,
                generation: None,
                resource_version: None,
                pruned: true,
                recorded_at: now,
            },
            now,
        );
    }

    /// Records every field the classifier needs from `metadata`.
    fn record_metadata(
        &self,
        cluster: &str,
        key: &ResourceKey,
        metadata: &ObjectMeta,
        now: Instant,
    ) {
        self.insert(
            EchoKey::new(cluster, key),
            EchoEntry {
                uid: metadata.uid.clone(),
                generation: metadata.generation,
                resource_version: metadata.resource_version.clone(),
                pruned: false,
                recorded_at: now,
            },
            now,
        );
    }

    /// Inserts `entry`, sweeping only when the cache is at capacity or the sweep is amortized due.
    ///
    /// Recording is on the sync path of every apply, so a full `retain` per write would make a
    /// 10 000-object fleet pay `O(n)` per resource. The sweep is therefore deferred: it runs when
    /// the map is at (or over) its cap — where it also bounds memory, because the insert that
    /// crosses the cap is the one that trims — or once every [`SWEEP_INTERVAL`] writes.
    fn insert(&self, key: EchoKey, entry: EchoEntry, now: Instant) {
        let mut state = lock_recover(&self.entries);
        state.entries.insert(key, entry);
        state.writes_since_sweep += 1;
        if state.entries.len() > self.capacity || state.writes_since_sweep >= SWEEP_INTERVAL {
            self.sweep(&mut state, now);
        }
    }

    /// Drops expired entries, then trims the cache to its cap in one sorted pass.
    fn sweep(&self, state: &mut EchoEntries, now: Instant) {
        let ttl = self.ttl;
        state.writes_since_sweep = 0;
        // One pass: everything the TTL would have dropped anyway.
        state
            .entries
            .retain(|_, held| now.saturating_duration_since(held.recorded_at) < ttl);
        let excess = state.entries.len().saturating_sub(self.capacity);
        if excess == 0 {
            return;
        }
        // Still over the cap (a fleet larger than `capacity`): the oldest recordings go first,
        // which is exactly the set the TTL would drop next. A fleet larger than the cap therefore
        // degrades to "an echo may cost one extra reconcile", never to unbounded memory. Sorting
        // once is what keeps this `O(n log n)` instead of the `O(n²)` of one scan per eviction.
        let mut ages: Vec<(Instant, EchoKey)> = state
            .entries
            .iter()
            .map(|(key, held)| (held.recorded_at, key.clone()))
            .collect();
        ages.sort_by_key(|(recorded_at, _)| *recorded_at);
        for (_, key) in ages.into_iter().take(excess) {
            state.entries.remove(&key);
        }
    }

    /// Returns why `observation` is FerrisCD's own write, or `None` when it is a real change.
    ///
    /// The lookup is by `(observation.cluster, observation.key)` (finding M-1), so a record made
    /// against one cluster is invisible to an event from another. A suppressed **`Delete`** marker is
    /// consumed by this call (finding M-2), so it can never suppress a later external delete.
    ///
    /// Expired entries are treated as absent **and** removed here, so a long-idle process does not
    /// accumulate dead records between sweeps.
    pub fn suppresses(
        &self,
        observation: &MetadataObservation<'_>,
        now: Instant,
    ) -> Option<SelfEcho> {
        let ttl = self.ttl;
        let key = EchoKey::new(observation.cluster, observation.key);
        let mut state = lock_recover(&self.entries);
        let expired = state
            .entries
            .get(&key)
            .map(|entry| now.saturating_duration_since(entry.recorded_at) >= ttl)?;
        if expired {
            state.entries.remove(&key);
            return None;
        }
        if observation.deleted {
            // Finding C1: a `Delete` event repeats the object's **last written** resource
            // version, so a matching version is not evidence that the delete was ours — an
            // external `kubectl delete` of an object we just applied carries exactly that
            // version, and suppressing it would hide the drift forever (nothing later corrects
            // a deleted object). Only a prune marker proves FerrisCD issued the delete.
            //
            // Finding M-2: the marker is one-shot. It is removed as it fires, so a prune followed
            // by a re-create (a `Replace`, a re-add to Git) cannot leave a durable marker behind
            // that would absorb the *next*, external delete of the same key.
            if !state.entries.get(&key)?.pruned {
                return None;
            }
            state.entries.remove(&key);
            return Some(SelfEcho::Prune);
        }
        let entry = state.entries.get(&key)?;
        let suppressed = match observation.generation {
            // Generation-bearing kind: only `(uid, generation)` proves "nothing but status moved".
            Some(generation) => {
                if entry.uid.is_some()
                    && entry.uid.as_deref() == observation.uid
                    && entry.generation == Some(generation)
                {
                    Some(SelfEcho::UnchangedGeneration)
                } else {
                    None
                }
            }
            // Generation-less kind: the resource version is the only evidence available.
            None => match (&entry.resource_version, observation.resource_version) {
                (Some(recorded), Some(observed)) if recorded == observed => Some(SelfEcho::Write),
                _ => None,
            },
        };
        // Finding M3: refresh the baseline of a `/status`-only write. Without this a long-lived
        // object whose status churns would lose its entry to the TTL and then trigger on the
        // next status-only event — a spurious reconcile per TTL, on the busiest objects we have.
        if suppressed == Some(SelfEcho::UnchangedGeneration)
            && let Some(held) = state.entries.get_mut(&key)
        {
            held.recorded_at = now;
        }
        suppressed
    }
}

/// Per-`Application` trailing debouncer (`2s`, ceiling `5s`).
///
/// A resource burst (one `kubectl apply -f` touching thirty objects of one `Application`) collapses
/// into one trigger: each event pushes the entry's `last` forward, so the entry becomes due once the
/// object has been quiet for [`DriftWatcherConfig::debounce`]. A continuously noisy object is capped
/// by `first + max_debounce`, so it still triggers every ceiling interval instead of never.
pub struct DriftDebouncer {
    pending: HashMap<reflector::ObjectRef<Application>, Pending>,
    debounce: Duration,
    max_debounce: Duration,
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    first: Instant,
    last: Instant,
}

impl std::fmt::Debug for DriftDebouncer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriftDebouncer")
            .field("pending", &self.pending.len())
            .field("debounce", &self.debounce)
            .field("max_debounce", &self.max_debounce)
            .finish()
    }
}

impl DriftDebouncer {
    /// Builds a debouncer with the given windows.
    #[must_use]
    pub fn new(debounce: Duration, max_debounce: Duration) -> Self {
        Self {
            pending: HashMap::new(),
            debounce,
            max_debounce: max_debounce.max(debounce),
        }
    }

    /// Arms (or re-arms) `app`.
    pub fn push(&mut self, app: reflector::ObjectRef<Application>, now: Instant) {
        self.pending
            .entry(app)
            .and_modify(|pending| pending.last = now)
            .or_insert(Pending {
                first: now,
                last: now,
            });
    }

    /// How many `Application`s are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// The earliest instant at which [`Self::take_due`] will yield something.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let debounce = self.debounce;
        let max_debounce = self.max_debounce;
        self.pending
            .values()
            .map(|pending| (pending.last + debounce).min(pending.first + max_debounce))
            .min()
    }

    /// Removes and returns every `Application` whose window has closed, sorted for determinism.
    pub fn take_due(&mut self, now: Instant) -> Vec<reflector::ObjectRef<Application>> {
        let debounce = self.debounce;
        let max_debounce = self.max_debounce;
        let due: Vec<reflector::ObjectRef<Application>> = self
            .pending
            .iter()
            .filter(|(_, pending)| {
                now.saturating_duration_since(pending.last) >= debounce
                    || now.saturating_duration_since(pending.first) >= max_debounce
            })
            .map(|(app, _)| app.clone())
            .collect();
        for app in &due {
            self.pending.remove(app);
        }
        let mut due = due;
        due.sort_by(|a, b| {
            (a.namespace.as_deref().unwrap_or_default(), &a.name)
                .cmp(&(b.namespace.as_deref().unwrap_or_default(), &b.name))
        });
        due
    }

    /// Removes and returns everything pending, regardless of the window.
    ///
    /// Used when a watch ends: the events were real, and the object may see no further event, so the
    /// pending triggers are flushed rather than discarded.
    pub fn take_all(&mut self) -> Vec<reflector::ObjectRef<Application>> {
        let mut all: Vec<reflector::ObjectRef<Application>> =
            self.pending.drain().map(|(app, _)| app).collect();
        all.sort_by(|a, b| {
            (a.namespace.as_deref().unwrap_or_default(), &a.name)
                .cmp(&(b.namespace.as_deref().unwrap_or_default(), &b.name))
        });
        all
    }
}

/// Index from `ferriscd.io/app-hash` to the `Application`s that own it.
///
/// Rebuilt from the controllers' own stores (never from the API), so it is bounded by the number of
/// `Application`s this replica watches. A hash collision (64 bits, negligible) maps to several
/// entries and simply triggers all of them: exact ownership is still verified against
/// `ferriscd.io/tracking-id` by the reconcile, so a collision costs one no-op pass.
#[derive(Debug, Default)]
pub struct AppHashIndex {
    by_hash: HashMap<String, Vec<reflector::ObjectRef<Application>>>,
}

impl AppHashIndex {
    /// Builds an empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the index with `apps`.
    pub fn rebuild<'a>(&mut self, apps: impl IntoIterator<Item = &'a Application>) {
        self.by_hash.clear();
        for app in apps {
            let namespace = app.namespace().unwrap_or_default();
            let name = app.name_any();
            let hash = ferriscd_engine::inventory::app_hash(&namespace, &name);
            let entry = self.by_hash.entry(hash).or_default();
            let reference = reflector::ObjectRef::new(&name);
            let reference = if namespace.is_empty() {
                reference
            } else {
                reference.within(&namespace)
            };
            if !entry.contains(&reference) {
                entry.push(reference);
            }
        }
        for refs in self.by_hash.values_mut() {
            refs.sort_by(|a, b| {
                (a.namespace.as_deref().unwrap_or_default(), &a.name)
                    .cmp(&(b.namespace.as_deref().unwrap_or_default(), &b.name))
            });
        }
    }

    /// The `Application`s claiming `hash`.
    #[must_use]
    pub fn lookup(&self, hash: &str) -> &[reflector::ObjectRef<Application>] {
        self.by_hash.get(hash).map(Vec::as_slice).unwrap_or(&[])
    }

    /// How many distinct hashes are indexed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_hash.len()
    }

    /// Whether the index is empty (no `Application` is reflected yet).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_hash.is_empty()
    }
}

/// One metadata-only observation, reduced to what the router needs.
///
/// Produced from a `PartialObjectMeta` and dropped immediately: the object itself is never retained,
/// so the watcher's memory is one entry per object in flight, not per object watched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedResource {
    /// The cluster the object was observed in (`WatchTarget::cluster`).
    ///
    /// Part of the echo lookup key (finding M-1): the same GKNN exists in every cluster, so an echo
    /// FerrisCD recorded against one destination must never suppress an event from another.
    pub cluster: String,
    /// Version-agnostic GKNN identity (`group`/`kind` come from the watch's `ApiResource`).
    pub key: ResourceKey,
    /// `metadata.uid`.
    pub uid: Option<String>,
    /// `metadata.generation` (absent for generation-less kinds).
    pub generation: Option<i64>,
    /// `metadata.resourceVersion`.
    pub resource_version: Option<String>,
    /// `ferriscd.io/app-hash`, when the object carries it.
    pub app_hash: Option<String>,
    /// Whether the source event was a `Delete`.
    pub deleted: bool,
}

impl ObservedResource {
    /// Reduces a metadata-only object to an observation.
    ///
    /// `cluster` is the cluster the watch runs against ([`WatchTarget::cluster`]); it is carried
    /// through to the echo lookup so a record made for another cluster can never match (finding
    /// M-1).
    #[must_use]
    pub fn from_metadata(
        cluster: impl Into<String>,
        api_resource: &ApiResource,
        metadata: &ObjectMeta,
        deleted: bool,
    ) -> Self {
        Self {
            cluster: cluster.into(),
            key: ResourceKey::new(
                api_resource.group.clone(),
                api_resource.kind.clone(),
                metadata.namespace.clone(),
                metadata.name.clone().unwrap_or_default(),
            ),
            uid: metadata.uid.clone(),
            generation: metadata.generation,
            resource_version: metadata.resource_version.clone(),
            app_hash: metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(annotations::LABEL_APP_HASH))
                .cloned(),
            deleted,
        }
    }

    /// The observation borrowed for the echo classifier.
    #[must_use]
    fn observation(&self) -> MetadataObservation<'_> {
        MetadataObservation {
            cluster: &self.cluster,
            key: &self.key,
            uid: self.uid.as_deref(),
            generation: self.generation,
            resource_version: self.resource_version.as_deref(),
            deleted: self.deleted,
        }
    }
}

/// What the router did with one observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriftDecision {
    /// The object was not going to be looked up (no `resourceVersion`).
    Ignored,
    /// FerrisCD's own write.
    Suppressed(SelfEcho),
    /// No watched `Application` claims the object's `ferriscd.io/app-hash`.
    Unmapped,
    /// Every claimant is outside this replica's shard or namespace scope.
    Filtered,
    /// `apps` `Application`s were armed (or re-armed) in the debouncer.
    Debounced {
        /// How many `Application`s this event armed.
        apps: usize,
    },
}

impl DriftDecision {
    /// The `outcome` label this decision records.
    #[must_use]
    pub fn outcome(self) -> DriftWatchOutcome {
        match self {
            Self::Ignored => DriftWatchOutcome::Ignored,
            Self::Suppressed(_) => DriftWatchOutcome::Suppressed,
            Self::Unmapped => DriftWatchOutcome::Unmapped,
            Self::Filtered => DriftWatchOutcome::Filtered,
            Self::Debounced { .. } => DriftWatchOutcome::Debounced,
        }
    }
}

/// The classification and coalescing core: echo → app-hash → shard → debounce.
///
/// Everything here is synchronous and clock-injected, which is what makes the whole state machine
/// provable in unit tests with a scripted event stream and **no sleeps**.
pub struct DriftRouter {
    echo: Arc<SelfEchoCache>,
    index: Arc<std::sync::RwLock<AppHashIndex>>,
    debouncer: DriftDebouncer,
    shard: Option<Sharding>,
    metrics: Option<Metrics>,
}

impl std::fmt::Debug for DriftRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriftRouter")
            .field("echo", &self.echo)
            .field("index", &read_recover(&self.index).len())
            .field("debouncer", &self.debouncer)
            .field("shard", &self.shard)
            .finish()
    }
}

impl DriftRouter {
    /// Builds a router over a shared echo cache and a shared app-hash index.
    #[must_use]
    pub fn new(
        config: &DriftWatcherConfig,
        shard: Option<Sharding>,
        echo: Arc<SelfEchoCache>,
        index: Arc<std::sync::RwLock<AppHashIndex>>,
        metrics: Option<Metrics>,
    ) -> Self {
        Self {
            echo,
            index,
            debouncer: DriftDebouncer::new(config.debounce, config.max_debounce),
            shard,
            metrics,
        }
    }

    /// The echo cache this router consults (shared with the sync path that writes it).
    #[must_use]
    pub fn echo(&self) -> &Arc<SelfEchoCache> {
        &self.echo
    }

    /// Classifies one observation and arms the debouncer for every owning `Application`.
    pub fn handle(&mut self, observed: &ObservedResource, now: Instant) -> DriftDecision {
        let decision = if observed.resource_version.is_none() {
            // Without a resource version nothing can be compared, so the event is not evidence.
            DriftDecision::Ignored
        } else if let Some(echo) = self.echo.suppresses(&observed.observation(), now) {
            DriftDecision::Suppressed(echo)
        } else {
            self.route(observed, now)
        };
        if let Some(metrics) = &self.metrics {
            metrics.record_drift_event(decision.outcome());
        }
        decision
    }

    /// Maps the object's `app-hash` to owning `Application`s and arms those this replica owns.
    fn route(&mut self, observed: &ObservedResource, now: Instant) -> DriftDecision {
        let Some(hash) = observed.app_hash.as_deref() else {
            // `ferriscd.io/managed-by=ferriscd` without an app-hash: an object stamped by a
            // different FerrisCD version, or one whose labels were edited. Nothing to trigger.
            return DriftDecision::Unmapped;
        };
        let claimants = read_recover(&self.index).lookup(hash).to_vec();
        if claimants.is_empty() {
            return DriftDecision::Unmapped;
        }
        let mut armed = 0_usize;
        for app in claimants {
            let namespace = app.namespace.clone().unwrap_or_default();
            if let Some(shard) = &self.shard
                && !shard.owns(&namespace, &app.name)
            {
                continue;
            }
            self.debouncer.push(app, now);
            armed += 1;
        }
        if armed == 0 {
            DriftDecision::Filtered
        } else {
            DriftDecision::Debounced { apps: armed }
        }
    }

    /// Removes and returns every `Application` whose debounce window has closed.
    ///
    /// The result is a *candidate* set: whether each one is really enqueued depends on the governed
    /// channel (a full queue drops it), so `ferriscd_drift_watcher_triggers_total` is incremented by
    /// [`DriftTriggerChannels::try_send`] and not here (finding M2).
    pub fn take_due(&mut self, now: Instant) -> Vec<reflector::ObjectRef<Application>> {
        self.debouncer.take_due(now)
    }

    /// Removes and returns everything pending (a watch ended).
    pub fn take_all(&mut self) -> Vec<reflector::ObjectRef<Application>> {
        self.debouncer.take_all()
    }

    /// When [`Self::take_due`] next has work, so the driver can sleep instead of polling.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.debouncer.next_deadline()
    }

    /// How many `Application`s are waiting for their window to close.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.debouncer.len()
    }
}

/// How a trigger was accepted by a scope's channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerDelivery {
    /// Handed to the owning scope's channel.
    Enqueued,
    /// The channel is full: the trigger is dropped (the periodic reconcile still converges).
    Full,
    /// The channel is closed: the scope's controller is gone (shutdown).
    Closed,
    /// No scope watches the `Application`'s namespace (a tenant scope that was not requested).
    NoScope,
}

impl TriggerDelivery {
    /// Whether the trigger reached a controller.
    #[must_use]
    pub fn is_enqueued(self) -> bool {
        matches!(self, Self::Enqueued)
    }
}

/// One scope's bounded trigger channel.
#[derive(Clone, Debug)]
struct ScopeTrigger {
    namespace: Option<String>,
    sender: mpsc::Sender<reflector::ObjectRef<Application>>,
}

/// Where the drift watcher hands its triggers: one bounded channel per `NamespacedController`.
///
/// A trigger for `Application` `ns/name` goes to the scope that watches `ns`, or to the
/// cluster-wide (`*`) scope when that is the configured one; anything else is reported as
/// [`TriggerDelivery::NoScope`] rather than silently reconciled by the wrong controller. Sending is
/// `try_send` only — a full queue must never stall a watch stream (trap guard).
#[derive(Clone, Debug)]
pub struct DriftTriggerChannels {
    scopes: Vec<ScopeTrigger>,
    metrics: Option<Metrics>,
}

impl DriftTriggerChannels {
    /// Builds the set of scope channels.
    #[must_use]
    pub fn new(
        scopes: Vec<(
            Option<String>,
            mpsc::Sender<reflector::ObjectRef<Application>>,
        )>,
        metrics: Option<Metrics>,
    ) -> Self {
        Self {
            scopes: scopes
                .into_iter()
                .map(|(namespace, sender)| ScopeTrigger { namespace, sender })
                .collect(),
            metrics,
        }
    }

    /// Attaches the process metric registry (builder style).
    ///
    /// Kept separate from [`Self::new`] because the channels are built where the controllers are
    /// (a plain `ControllerConfig` value) while the registry belongs to the process.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Option<Metrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// How many scope channels are wired.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scopes.len()
    }

    /// Whether no scope channel is wired (the watcher is disabled).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }

    /// Delivers `app`, preferring an exact namespace scope over the cluster-wide one.
    pub fn deliver(&self, app: &reflector::ObjectRef<Application>) -> TriggerDelivery {
        let namespace = app.namespace.as_deref().unwrap_or_default();
        let exact = self
            .scopes
            .iter()
            .find(|scope| scope.namespace.as_deref() == Some(namespace));
        let selected = exact.or_else(|| self.scopes.iter().find(|scope| scope.namespace.is_none()));
        let Some(scope) = selected else {
            return TriggerDelivery::NoScope;
        };
        match scope.sender.try_send(app.clone()) {
            Ok(()) => TriggerDelivery::Enqueued,
            Err(mpsc::error::TrySendError::Full(_)) => TriggerDelivery::Full,
            Err(mpsc::error::TrySendError::Closed(_)) => TriggerDelivery::Closed,
        }
    }

    /// Delivers `app` and records the outcome (drops are counted, never logged per event).
    ///
    /// This is the only place `ferriscd_drift_watcher_triggers_total` moves, so the counter means
    /// exactly "reconciles a drift trigger enqueued" — a trigger the bounded queue refused is
    /// counted as `dropped` instead, never as a trigger (finding M2).
    pub fn try_send(&self, app: &reflector::ObjectRef<Application>) -> TriggerDelivery {
        let delivery = self.deliver(app);
        if let Some(metrics) = &self.metrics {
            if delivery.is_enqueued() {
                metrics.record_drift_trigger();
            } else {
                // A dropped trigger is observable but not error-level: the bounded queue is the
                // back-pressure contract, and Model 1 still converges the Application.
                metrics.record_drift_event(DriftWatchOutcome::Dropped);
            }
        }
        delivery
    }
}

/// How a metadata watch stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DriftStreamOutcome {
    /// The stream ended on its own (the watcher was dropped or the API server closed it).
    Ended,
    /// The shared stop token was cancelled.
    Stopped,
    /// The watch cannot work in this configuration: park on the fallback cooldown.
    Fallback(DriftFallbackReason),
}

/// Parking state of one `(cluster, GVK)` watch after a permanent failure.
///
/// Kept as a value (not a `sleep`) so the cooldown arithmetic is provable with an injected clock:
/// [`Self::is_parked`] is the whole question the supervisor asks before building a new stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FallbackState {
    parked_until: Option<Instant>,
    reason: Option<DriftFallbackReason>,
}

impl FallbackState {
    /// Parks until `now + cooldown`.
    pub fn park(&mut self, reason: DriftFallbackReason, now: Instant, cooldown: Duration) {
        self.parked_until = Some(now + cooldown);
        self.reason = Some(reason);
    }

    /// Whether the watcher is still inside its cooldown at `now`.
    ///
    /// The boundary is exclusive: [`Self::park`] starts the window at the failure instant, so at
    /// exactly `now == parked_until` the cooldown has expired and the watch may be retried. A
    /// watcher that never parked is never parked, so this is the whole question the supervisor asks
    /// before it builds a new stream.
    #[must_use]
    pub fn is_parked(&self, now: Instant) -> bool {
        self.parked_until.is_some_and(|until| now < until)
    }

    /// The reason of the last parking, if any.
    #[must_use]
    pub fn reason(&self) -> Option<DriftFallbackReason> {
        self.reason
    }

    /// The instant the parking ends.
    #[must_use]
    pub fn parked_until(&self) -> Option<Instant> {
        self.parked_until
    }
}

/// Injectable clock.
///
/// The debouncer, the echo TTL and the fallback cooldown are all expressed against this, so a unit
/// test drives days of window arithmetic in microseconds and never calls `sleep` on the wall clock.
pub trait DriftClock: Send + Sync + 'static {
    /// The current instant.
    fn now(&self) -> Instant;

    /// Resolves when `deadline` has passed, or never when there is no deadline.
    fn sleep_until(&self, deadline: Option<Instant>) -> BoxFuture<'static, ()>;
}

/// The production clock: `std::time::Instant` and `tokio::time::sleep_until`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDriftClock;

impl DriftClock for SystemDriftClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep_until(&self, deadline: Option<Instant>) -> BoxFuture<'static, ()> {
        match deadline {
            Some(deadline) => Box::pin(tokio::time::sleep_until(deadline.into())),
            // No pending debounce entry: wake only when the stream or the stop token does.
            None => Box::pin(futures::future::pending()),
        }
    }
}

/// Classifies a watch error into a permanent fallback reason.
///
/// Only `403`/`404`/`405` are permanent: a `429`, a `500`, a `410 Gone` or a dropped connection is
/// handled by `kube`'s own watch backoff and must **not** park the watcher.
impl DriftFallbackReason {
    /// The fallback reason for `error`, or `None` when it is transient.
    #[must_use]
    pub fn of_watch_error(error: &watcher::Error) -> Option<Self> {
        match error {
            watcher::Error::InitialListFailed(source)
            | watcher::Error::WatchStartFailed(source)
            | watcher::Error::WatchFailed(source) => match source {
                kube::Error::Api(status) => Self::of_code(status.code),
                _ => None,
            },
            watcher::Error::WatchError(status) => Self::of_code(status.code),
            watcher::Error::NoResourceVersion => None,
        }
    }
}

/// Drives one metadata watch stream into the router until it ends, stops, or must fall back.
///
/// The loop is the whole event path: flush what the debouncer owes, then wait for either the next
/// event, the next debounce deadline, or shutdown. Triggers are delivered with `try_send` through
/// [`DriftTriggerChannels::try_send`], so this future never blocks on a controller queue.
///
/// `cluster` is the cluster this stream watches ([`WatchTarget::cluster`]); every observation is
/// tagged with it so the echo lookup only ever matches a write made against the same cluster
/// (finding M-1).
pub async fn drive_metadata_stream<S, C>(
    stream: S,
    router: &Mutex<DriftRouter>,
    cluster: &str,
    api_resource: &ApiResource,
    channels: &DriftTriggerChannels,
    clock: &C,
    stop: &CancellationToken,
) -> DriftStreamOutcome
where
    S: Stream<Item = Result<watcher::Event<PartialObjectMeta<DynamicObject>>, watcher::Error>>,
    C: DriftClock,
{
    // Boxed because `kube`'s watch stream is deliberately `!Unpin` (it holds a pinned `unfold`).
    let mut stream = Box::pin(stream);
    loop {
        // Whatever is due goes first: a burst inside one debounce window must not be delayed by a
        // quiet stream that has no further events to wake us.
        for app in lock_recover(router).take_due(clock.now()) {
            channels.try_send(&app);
        }
        let deadline = lock_recover(router).next_deadline();
        tokio::select! {
            biased;
            () = stop.cancelled() => return DriftStreamOutcome::Stopped,
            item = stream.next() => match item {
                // The watch ended (the controller dropped it, or the API server closed it): flush
                // what is pending, because the objects may see no further event on this stream.
                None => {
                    for app in lock_recover(router).take_all() {
                        channels.try_send(&app);
                    }
                    return DriftStreamOutcome::Ended;
                }
                Some(Ok(watcher::Event::Init)) => {
                    tracing::trace!("drift watch re-list started; seeding baselines without triggering");
                }
                // A re-list is the observed state, not drift: seed the baseline and stay quiet.
                Some(Ok(watcher::Event::InitApply(object))) => {
                    let observed =
                        ObservedResource::from_metadata(cluster, api_resource, &object.metadata, false);
                    lock_recover(router).echo().record_baseline(
                        &observed.cluster,
                        &observed.key,
                        &object.metadata,
                        clock.now(),
                    );
                }
                Some(Ok(watcher::Event::InitDone)) => {
                    tracing::trace!("drift watch re-list complete");
                }
                Some(Ok(watcher::Event::Apply(object))) => {
                    let observed =
                        ObservedResource::from_metadata(cluster, api_resource, &object.metadata, false);
                    lock_recover(router).handle(&observed, clock.now());
                }
                Some(Ok(watcher::Event::Delete(object))) => {
                    let observed =
                        ObservedResource::from_metadata(cluster, api_resource, &object.metadata, true);
                    lock_recover(router).handle(&observed, clock.now());
                }
                Some(Err(error)) => {
                    if let Some(reason) = DriftFallbackReason::of_watch_error(&error) {
                        return DriftStreamOutcome::Fallback(reason);
                    }
                    // Transient: `kube`'s watcher retries internally, so this is a trace line, not
                    // a state change. Never parks the watcher, never marks an Application unhealthy.
                    tracing::debug!(
                        api_resource = %api_resource.kind,
                        error = %error,
                        "drift watch error (transient); kube will retry"
                    );
                }
            },
            () = clock.sleep_until(deadline) => {}
        }
    }
}

/// One `(cluster, group/kind)` pair that should be watched.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WatchRequest {
    /// Cluster name (`in-cluster`, or a registered remote).
    pub cluster: String,
    /// API group (empty for the core group).
    pub group: String,
    /// Resource kind.
    pub kind: String,
    /// Version hint from `status.inventory` (may be empty: resolve by `group`/`kind` then).
    pub version: String,
}

impl WatchRequest {
    /// Version-agnostic `group`/`kind` of this request.
    #[must_use]
    pub fn group_kind(&self) -> GroupKind {
        GroupKind::new(&self.group, &self.kind)
    }
}

/// The deduplicated, filtered, per-cluster capped set of watches to run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchPlan {
    /// The requests to watch, sorted by `(cluster, group, kind)`.
    pub requests: Vec<WatchRequest>,
    /// How many requests per cluster were dropped by [`MAX_DRIFT_WATCHES`].
    pub capped: BTreeMap<String, usize>,
    /// How many inventory entries could not be parsed as GKNN (never fatal).
    pub unparsed: usize,
}

/// Derives the watch set from the watched `Application`s' inventories.
///
/// `apps` is an iterator of `(destination cluster, status.inventory entries)`; the cluster is
/// **trimmed** here, so a padded `spec.destination.cluster` plans under the one spelling every
/// other component uses (see the comment in the loop). The result is
/// deduplicated (two `Application`s deploying the same `ConfigMap` kind in one cluster share one
/// watch), filtered by [`DriftKindFilter`], and capped **per cluster** at `max_watches` in sorted
/// order, so the same fleet always yields the same watches and the excess is reported instead of
/// silently unpredictable.
#[must_use]
pub fn plan_watch_requests<'a, I>(
    apps: I,
    filter: &DriftKindFilter,
    max_watches: usize,
) -> WatchPlan
where
    I: IntoIterator<Item = (&'a str, &'a [StatusInventoryEntry])>,
{
    let mut plan = WatchPlan::default();
    // Keyed by `(cluster, group, kind)` — **never** by `version`: identity in FerrisCD is
    // version-agnostic (GKNN), so two `Application`s reporting `v1` and `v1beta1` for the
    // same `Deployment` must share one watch, not spend two of the sixty-four on the same kind. The
    // versions become a hint (see [`WatchRequest::version`]) and the first non-empty one wins
    // deterministically.
    let mut seen: BTreeMap<(String, String, String), BTreeSet<String>> = BTreeMap::new();
    for (cluster, inventory) in apps {
        // Finding M: `spec.destination.cluster` is **trimmed** everywhere else — `sync.rs` trims it
        // before the project policy sees it and `ClusterManager::get` trims it before the handle
        // lookup — so `"  in-cluster  "` and `"in-cluster"` are the same cluster. Planning under the
        // raw spelling would put a request in the plan that `watch_keys` can never match against the
        // registry's `names()` (`wanted`), while `resolve_watch_targets` *would* resolve it: the
        // watch would be spawned by one refresh and cancelled by the next, forever. One spelling
        // for the plan, the watch key, the echo record and every log line.
        let cluster = cluster.trim();
        for entry in inventory {
            // Reuse the one GKNN parser (`from_status_entries`) instead of duplicating its rules;
            // a malformed entry is counted and skipped, because one odd `/status` must not stop
            // drift detection for the whole fleet.
            let Ok(inventory) = from_status_entries(std::iter::once(entry)) else {
                plan.unparsed += 1;
                continue;
            };
            for (key, held) in inventory {
                if !filter.allows(&key.group, &key.kind) {
                    continue;
                }
                seen.entry((cluster.to_owned(), key.group, key.kind))
                    .or_default()
                    .insert(held.version);
            }
        }
    }
    let max_watches = max_watches.max(1);
    let mut per_cluster: BTreeMap<String, usize> = BTreeMap::new();
    for ((cluster, group, kind), versions) in seen {
        let request = WatchRequest {
            cluster,
            group,
            kind,
            // A non-empty hint is an optimisation only: `resolve_watch_targets` falls back to the
            // served version of the kind when the hint does not resolve.
            version: versions
                .into_iter()
                .find(|version| !version.is_empty())
                .unwrap_or_default(),
        };
        let taken = per_cluster.entry(request.cluster.clone()).or_default();
        if *taken >= max_watches {
            *plan.capped.entry(request.cluster.clone()).or_default() += 1;
            continue;
        }
        *taken += 1;
        plan.requests.push(request);
    }
    plan
}

/// The `(cluster, group/kind)` watches that must be running for `plan` right now.
///
/// `addressable` is [`IN_CLUSTER`] plus [`ClusterManager::names`]. Filtering by it (rather than
/// trusting the plan alone) is what makes a **lagged** lifecycle subscriber safe: an `Application`
/// that still points at a revoked cluster keeps a request in the plan, so only the registry's
/// current view can tell the supervisor to cancel that watch. Everything the filter drops is also
/// dropped by [`resolve_watch_targets`] (the cluster no longer resolves), so this only closes the
/// window in which a watch would otherwise run on credentials the registry already revoked.
fn watch_keys(plan: &WatchPlan, addressable: &BTreeSet<String>) -> BTreeSet<(String, GroupKind)> {
    plan.requests
        .iter()
        .filter(|request| addressable.contains(request.cluster.as_str()))
        .map(|request| (request.cluster.clone(), request.group_kind()))
        .collect()
}

/// Whether a resolved target may be spawned, i.e. whether it is in the current `wanted` set.
///
/// The supervisor's last gate before it starts a task (finding M): cancelling is driven by
/// `running.retain(|key, _| wanted.contains(key))`, so spawning anything `wanted` does not hold
/// guarantees the very next refresh cancels it — the spawn/cancel cycle a padded
/// `spec.destination.cluster` used to produce. Both sides are keyed by the same `(cluster,
/// group/kind)` pair the running map uses, so the gate cannot drift from it.
fn admits(wanted: &BTreeSet<(String, GroupKind)>, target: &WatchTarget) -> bool {
    wanted.contains(&(target.cluster.clone(), target.group_kind()))
}

/// One resolved watch: an `ApiResource` on one cluster.
#[derive(Clone)]
pub struct WatchTarget {
    /// Cluster name: the **trimmed** `spec.destination.cluster` the watch was planned under, so it
    /// matches `watch_keys`/`wanted` and the echo record byte for byte.
    pub cluster: String,
    /// Discovered resource (real plural name and served version).
    pub api_resource: ApiResource,
    /// The client of the cluster the watch runs against.
    pub client: kube::Client,
}

impl std::fmt::Debug for WatchTarget {
    /// Manual, because `kube::Client` deliberately has no `Debug` (it would print the connector).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WatchTarget")
            .field("cluster", &self.cluster)
            .field("api_resource", &self.api_resource)
            .finish_non_exhaustive()
    }
}

impl WatchTarget {
    /// Version-agnostic `group`/`kind` of this target.
    #[must_use]
    pub fn group_kind(&self) -> GroupKind {
        GroupKind::new(&self.api_resource.group, &self.api_resource.kind)
    }
}

/// Resolves planned requests against each cluster's discovery cache.
///
/// A request that the cluster does not serve (a CRD removed since the inventory was written, or a
/// remote cluster with a different API surface) is skipped and counted: the `Application`'s
/// periodic reconcile will notice, and a watcher must never fail the process for one missing kind.
pub async fn resolve_watch_targets(
    plan: &WatchPlan,
    clusters: &ClusterManager,
) -> (Vec<WatchTarget>, usize) {
    let mut targets = Vec::new();
    let mut unresolved = 0_usize;
    for request in &plan.requests {
        let Ok(handle) = clusters.get(&request.cluster) else {
            unresolved += 1;
            continue;
        };
        let resolved = match request.version.is_empty() {
            false => {
                let gvk = GroupVersionKind::gvk(&request.group, &request.version, &request.kind);
                handle.discovery().resolve(&gvk).await.ok()
            }
            true => None,
        };
        let resolved = match resolved {
            Some(found) => Some(found),
            // No (or an unusable) version hint: identity in FerrisCD is version-agnostic, so the
            // first served version of the kind is the right answer.
            None => handle
                .discovery()
                .resolve_kind(&request.group, &request.kind)
                .await
                .ok()
                .flatten(),
        };
        match resolved {
            Some((api_resource, _capabilities)) => targets.push(WatchTarget {
                cluster: request.cluster.clone(),
                api_resource,
                client: handle.client().clone(),
            }),
            None => {
                unresolved += 1;
                tracing::debug!(
                    cluster = %request.cluster,
                    group = %request.group,
                    kind = %request.kind,
                    "drift watcher: the cluster does not serve this kind; skipping the watch"
                );
            }
        }
    }
    (targets, unresolved)
}

/// The collaborators the drift supervisor needs but the controller set does not own.
///
/// Built by [`crate::prepare`], passed per leader term: the registry (for cluster lifecycle events),
/// the self-echo cache (shared with the sync pipeline that records into it) and the process metric
/// registry. `None` when `--enable-drift-watcher` is off, in which case nothing is started.
#[derive(Clone)]
pub struct DriftRuntime {
    /// The cluster registry: the source of per-cluster clients, discovery caches and lifecycle
    /// events.
    pub clusters: Arc<ClusterManager>,
    /// The self-echo cache the pipeline records every confirmed write into.
    pub echo: Arc<SelfEchoCache>,
    /// The process metric registry (optional: the library default builds none).
    pub metrics: Option<Metrics>,
}

impl std::fmt::Debug for DriftRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriftRuntime")
            .field("clusters", &self.clusters.names())
            .field("echo", &self.echo)
            .field("metrics", &self.metrics.is_some())
            .finish()
    }
}

/// The long-running supervisor of the opt-in drift watcher.
///
/// One task owns every per-`(cluster, GVK)` metadata watch, keeps the app-hash index in step with the
/// `Application` stores, and reacts to [`ClusterLifecycleEvent`]s (a removed cluster stops its
/// watches at once; an added or rebuilt cluster starts fresh ones with the new client).
pub struct DriftWatcher {
    config: DriftWatcherConfig,
    clusters: Arc<ClusterManager>,
    stores: Vec<Store<Application>>,
    channels: Arc<DriftTriggerChannels>,
    router: Arc<Mutex<DriftRouter>>,
    index: Arc<std::sync::RwLock<AppHashIndex>>,
    metrics: Option<Metrics>,
}

impl std::fmt::Debug for DriftWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DriftWatcher")
            .field("config", &self.config)
            .field("scopes", &self.stores.len())
            .field("clusters", &self.clusters.names())
            .field("router", &lock_recover(&self.router).pending())
            .finish_non_exhaustive()
    }
}

impl DriftWatcher {
    /// Builds the supervisor. `echo` is the cache the sync path records into.
    #[must_use]
    pub fn new(
        config: DriftWatcherConfig,
        clusters: Arc<ClusterManager>,
        stores: Vec<Store<Application>>,
        channels: Arc<DriftTriggerChannels>,
        echo: Arc<SelfEchoCache>,
        shard: Option<Sharding>,
        metrics: Option<Metrics>,
    ) -> Self {
        let index = Arc::new(std::sync::RwLock::new(AppHashIndex::new()));
        let router = Arc::new(Mutex::new(DriftRouter::new(
            &config,
            shard,
            echo,
            index.clone(),
            metrics.clone(),
        )));
        Self {
            config,
            clusters,
            stores,
            channels,
            router,
            index,
            metrics,
        }
    }

    /// The shared router (so a caller can assert the state in tests).
    #[must_use]
    pub fn router(&self) -> &Arc<Mutex<DriftRouter>> {
        &self.router
    }

    /// Rebuilds the app-hash index from the `Application` stores and returns the current plan.
    ///
    /// Called on every cluster lifecycle event and on every [`WATCH_REFRESH_INTERVAL`] tick; the cost
    /// is one pass over the `Application`s this replica already holds in memory.
    #[must_use]
    pub fn plan(&self) -> WatchPlan {
        let apps: Vec<Arc<Application>> = self.stores.iter().flat_map(Store::state).collect();
        write_recover(&self.index).rebuild(apps.iter().map(AsRef::as_ref));
        let inventories: Vec<(&str, &[StatusInventoryEntry])> = apps
            .iter()
            .map(|app| {
                (
                    app.spec.destination.cluster.as_str(),
                    app.status
                        .as_ref()
                        .map(|status| status.inventory.as_slice())
                        .unwrap_or(&[]),
                )
            })
            .collect();
        plan_watch_requests(inventories, &self.config.kinds, self.config.max_watches)
    }

    /// Runs until `stop` is cancelled.
    ///
    /// The active set is recomputed on every cluster lifecycle event and on each refresh tick, and
    /// reconciled against the running watches **by identity**: a watch whose `(cluster, GVK)` left
    /// the plan (or whose cluster was removed) is cancelled, a pair that entered it is started, and
    /// a watch whose target did not change is left completely alone. Leaving it alone is not an
    /// optimisation: rebuilding it would throw away its [`FallbackState`], so a kind the API server
    /// refuses (`403`) would retry — and log, and count — on every 30 s refresh instead of once per
    /// [`FALLBACK_COOLDOWN`], and every watch would re-list its whole kind for nothing (finding C2).
    ///
    /// A watch that parked on a permanent failure is *not* respawned until its cooldown expires; the
    /// parking state survives a respawn (a rebuilt cluster client, a new served version), so the
    /// cooldown is never reset by the supervisor.
    ///
    /// A slow subscriber that lagged behind resynchronises against the recomputed plan, exactly as
    /// [`ClusterManager::subscribe`] documents.
    pub async fn run(self, stop: CancellationToken) {
        tracing::info!(
            max_watches = self.config.max_watches,
            kinds = ?self.config.kinds.kinds(),
            scopes = self.stores.len(),
            selector = %label_selector(),
            "opt-in drift watcher started (PartialObjectMetadata watches, label-scoped)"
        );
        let mut events = self.clusters.subscribe();
        // Keyed by `(cluster, group/kind)`: the same kind on two clusters is two independent
        // watches, and a `Rebuilt` cluster must replace only its own.
        let mut running: BTreeMap<(String, GroupKind), RunningWatch> = BTreeMap::new();
        // Parking states of watches that are *not* running (they hit a permanent error and were not
        // respawned). Kept outside `running` so the active gauge never counts a parked watch.
        let mut parked: BTreeMap<(String, GroupKind), SharedFallback> = BTreeMap::new();
        // Bumped on `Added`/`Rebuilt`/`Removed`: a cluster whose client was rebuilt must be watched
        // through a new stream, and nothing else may be touched.
        //
        // Finding N-2: an entry is never dropped again, so the map holds one `u64` per cluster name
        // the registry has *ever* reported — bounded by the number of registrations an operator
        // created, not by the fleet, so it is left alone rather than rebuilt per refresh.
        let mut epochs: BTreeMap<String, u64> = BTreeMap::new();
        // Last logged plan diagnostics: a steady-state misconfiguration is warned about once per
        // *change*, not once per refresh (which would be a 30 s warn/log-spam loop).
        let mut logged = PlanDiagnostics::default();
        let mut tick = tokio::time::interval(WATCH_REFRESH_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let refresh = tokio::select! {
                () = stop.cancelled() => break,
                _ = tick.tick() => true,
                event = events.recv() => match event {
                    Ok(ClusterLifecycleEvent::Added(name))
                    | Ok(ClusterLifecycleEvent::Rebuilt(name)) => {
                        tracing::info!(cluster = %name, "drift watcher: cluster became addressable; refreshing watches");
                        // A new or rebuilt client: only this cluster's watches are replaced.
                        *epochs.entry(name).or_default() += 1;
                        true
                    }
                    Ok(ClusterLifecycleEvent::Removed(name)) => {
                        tracing::info!(cluster = %name, "drift watcher: cluster removed; cancelling its watches");
                        *epochs.entry(name.clone()).or_default() += 1;
                        running.retain(|(cluster, _), watch| {
                            if cluster == &name {
                                watch.stop.cancel();
                                false
                            } else {
                                true
                            }
                        });
                        // The cluster is gone: its cooldowns are dead weight nobody will consult.
                        parked.retain(|(cluster, _), _| cluster != &name);
                        true
                    }
                    // The registry never waits for a subscriber: a lagged consumer rebuilds from
                    // the authoritative `names()` snapshot, which the plan already is.
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "drift watcher fell behind the cluster lifecycle broadcast; resynchronising from the plan");
                        true
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => false,
                },
            };
            if !refresh {
                break;
            }
            let plan = self.plan();
            logged.report(&plan, self.config.max_watches);
            // A `Removed` event that arrived while this subscriber was lagged must still cancel the
            // dead cluster's watches, so the set of watchers is filtered by what the registry says is
            // addressable right now (`IN_CLUSTER` plus the registered names) instead of by the plan
            // alone. Without this the plan would keep naming a revoked cluster — an `Application`
            // that still points at it keeps the request alive — and the old watch would keep running
            // on credentials the registry already dropped.
            let mut addressable: BTreeSet<String> = self.clusters.names().into_iter().collect();
            addressable.insert(IN_CLUSTER.to_owned());
            let wanted = watch_keys(&plan, &addressable);
            // Cancel watches that left the plan (a kind removed from every inventory, or a cluster
            // whose registration was revoked).
            running.retain(|key, watch| {
                if wanted.contains(key) {
                    true
                } else {
                    watch.stop.cancel();
                    false
                }
            });
            let now = SystemDriftClock.now();
            // A cooldown is dropped once it has expired and its key is no longer wanted: nothing
            // will consult it again, and keeping it would leak one entry per retired kind.
            parked.retain(|key, state| wanted.contains(key) || lock_recover(state).is_parked(now));
            let (targets, unresolved) = resolve_watch_targets(&plan, &self.clusters).await;
            if unresolved > 0 {
                tracing::debug!(
                    unresolved,
                    "drift watcher: some planned kinds are not served; started the rest"
                );
            }
            for target in targets {
                let key = (target.cluster.clone(), target.group_kind());
                // Finding M: `wanted` is **authoritative** for spawning. It is the only set that is
                // checked against the registry's live `names()`, so a target the plan resolved under
                // a spelling (or a cluster) `wanted` does not hold must not start a task: the next
                // refresh would cancel it again, and the pair would be rebuilt on every refresh
                // forever (re-listing its whole kind each time). Resolution is a hint about what the
                // API server serves; `wanted` decides what this replica watches.
                if !admits(&wanted, &target) {
                    tracing::debug!(
                        cluster = %target.cluster,
                        group = %target.api_resource.group,
                        kind = %target.api_resource.kind,
                        "drift watcher: the plan resolved a target the current watch set does not \
                         want; not spawning it"
                    );
                    continue;
                }
                let epoch = *epochs.entry(target.cluster.clone()).or_default();
                match watch_disposition(running.get(&key), parked.get(&key), &target, epoch, now) {
                    // Unchanged: the running task keeps its stream, its parking state and its
                    // backoff. Cancelling it here is exactly the C2 regression.
                    WatchDisposition::Keep => continue,
                    // Parked on a permanent failure: do not build a stream the API server will
                    // refuse again. The next refresh retries once the cooldown has expired.
                    WatchDisposition::Parked => {
                        // A *changed* target under a parked watch still stops the old task: it may
                        // be holding a client the registry has already rebuilt (revoked
                        // credentials). The cooldown is carried over, so a rebuilt cluster does not
                        // become a retry loop.
                        if let Some(previous) = running.remove(&key) {
                            previous.stop.cancel();
                            parked.insert(key, previous.state);
                        }
                        continue;
                    }
                    WatchDisposition::Spawn => {}
                }
                // The target changed (a rebuilt client, a new served version, a first spawn): the
                // old task must stop before the new one lists.
                let previous = running.remove(&key);
                let state = previous
                    .as_ref()
                    .map(|watch| watch.state.clone())
                    .or_else(|| parked.remove(&key))
                    .unwrap_or_else(|| Arc::new(Mutex::new(FallbackState::default())));
                if let Some(previous) = previous {
                    previous.stop.cancel();
                }
                let active = Arc::new(AtomicBool::new(false));
                let token = CancellationToken::new();
                let router = self.router.clone();
                let channels = self.channels.clone();
                let config = self.config.clone();
                let metrics = self.metrics.clone();
                running.insert(
                    key,
                    RunningWatch {
                        api_resource: target.api_resource.clone(),
                        epoch,
                        state: state.clone(),
                        active: active.clone(),
                        stop: token.clone(),
                    },
                );
                tokio::spawn(async move {
                    run_one_watch(
                        WatchTask {
                            target,
                            state,
                            active,
                            stop: token,
                        },
                        config,
                        router,
                        channels,
                        metrics,
                    )
                    .await;
                });
            }
            if let Some(metrics) = &self.metrics {
                // Only a streaming task is an active watch: a parked or restart-delayed one is not.
                //
                // Finding N-3: the gauge is *sampled* here, at the end of a refresh iteration (one
                // per lifecycle event or per `WATCH_REFRESH_INTERVAL`). A task that starts or dies in
                // between is reflected on the next refresh, so the gauge may lag by up to one refresh
                // interval. It is a capacity signal, never a per-event counter, so it is deliberately
                // not bumped from inside the tasks (which would need a second lock on the hot path).
                metrics.set_drift_active_watches(active_watches(&running));
            }
        }
        // Shutdown: cancel every watch and report the gauge back to zero.
        for (_, watch) in running {
            watch.stop.cancel();
        }
        if let Some(metrics) = &self.metrics {
            metrics.set_drift_active_watches(0);
        }
        tracing::info!("opt-in drift watcher stopped");
    }
}

/// A parking state shared between the supervisor and one watch task.
pub(crate) type SharedFallback = Arc<Mutex<FallbackState>>;

/// One running `(cluster, group/kind)` watch, as the supervisor sees it.
pub(crate) struct RunningWatch {
    /// The discovered resource the watch was built for (a served version that moved is a new watch).
    api_resource: ApiResource,
    /// The cluster epoch at spawn: `Added`/`Rebuilt`/`Removed` bump it, so a new client replaces
    /// the stream even when the resource itself did not change.
    epoch: u64,
    /// The parking state of the task, shared with it so a respawn resumes the same cooldown.
    state: SharedFallback,
    /// Whether the task is streaming right now (a parked or restart-delayed task is not active).
    active: Arc<AtomicBool>,
    /// Cancels the task.
    stop: CancellationToken,
}

impl RunningWatch {
    /// Whether this watch already runs exactly `target` at `epoch`.
    fn matches(&self, target: &WatchTarget, epoch: u64) -> bool {
        self.epoch == epoch && self.api_resource == target.api_resource
    }

    /// Whether the task is streaming right now.
    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

/// What the supervisor must do with one resolved target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WatchDisposition {
    /// The running watch already has this target at this epoch: touch nothing.
    Keep,
    /// The watch parked on a permanent failure and its cooldown has not expired: do not respawn it.
    Parked,
    /// Start a watch (no running one, a changed target, or an expired cooldown).
    Spawn,
}

/// Decides whether one resolved target needs a new watch task (`T18.2` finding C2).
///
/// Pure and clock-injected, so the regression it prevents is provable without a cluster: the
/// supervisor must return [`WatchDisposition::Keep`] for an unchanged target (otherwise every 30 s
/// refresh rebuilds every watch, re-lists every kind and resets the fallback state), and
/// [`WatchDisposition::Parked`] for a watch inside its cooldown (otherwise a permanently refused
/// kind retries, logs and counts on every refresh instead of once per cooldown).
#[must_use]
pub(crate) fn watch_disposition(
    running: Option<&RunningWatch>,
    parked: Option<&SharedFallback>,
    target: &WatchTarget,
    epoch: u64,
    now: Instant,
) -> WatchDisposition {
    if running.is_some_and(|watch| watch.matches(target, epoch)) {
        return WatchDisposition::Keep;
    }
    // A target change does not clear a cooldown: the refused *kind* (or the RBAC that refuses it) is
    // what parked the watch, and a new client is no evidence that it changed.
    let state = parked.or_else(|| running.map(|watch| &watch.state));
    match state {
        Some(state) if lock_recover(state).is_parked(now) => WatchDisposition::Parked,
        _ => WatchDisposition::Spawn,
    }
}

/// How many running watches are actually streaming (a parked or restart-delayed one is not).
#[must_use]
pub(crate) fn active_watches(running: &BTreeMap<(String, GroupKind), RunningWatch>) -> usize {
    running.values().filter(|watch| watch.is_active()).count()
}

/// The plan diagnostics that are logged once per *change* rather than once per refresh.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct PlanDiagnostics {
    capped: BTreeMap<String, usize>,
    unparsed: usize,
}

impl PlanDiagnostics {
    /// Logs the cap and GKNN warnings, but only when they differ from the last logged state.
    ///
    /// A capped or malformed inventory is a steady state, not an event: logging it on every 30 s
    /// refresh buries the one line that matters and gives an operator a warn-per-30 s heartbeat.
    fn report(&mut self, plan: &WatchPlan, max_watches: usize) {
        if plan.capped != self.capped {
            if plan.capped.is_empty() {
                tracing::info!(
                    "drift watcher: the inventory fits the per-cluster watch ceiling again"
                );
            } else {
                tracing::warn!(
                    capped = ?plan.capped,
                    max_watches,
                    "drift watcher: the inventory asks for more watches than the per-cluster \
                     ceiling; the excess stays on periodic polling"
                );
            }
            self.capped = plan.capped.clone();
        }
        if plan.unparsed != self.unparsed {
            if plan.unparsed == 0 {
                tracing::info!("drift watcher: every status.inventory key is canonical GKNN again");
            } else {
                tracing::warn!(
                    unparsed = plan.unparsed,
                    "drift watcher: some status.inventory keys are not canonical GKNN and were \
                     skipped"
                );
            }
            self.unparsed = plan.unparsed;
        }
    }
}

/// What the supervisor does with a `(cluster, GVK)` watch after its stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WatchStep {
    /// Build a fresh stream and keep watching (transient end, or after the cooldown expires).
    Restart,
    /// The watcher was cancelled: the task returns.
    Stop,
}

/// Records a permanent watch failure and parks the watch.
///
/// This is the whole fallback contract in one synchronous, clock-injected function, so the `T18.2`
/// acceptance criterion ("`403` falls back cleanly and increments the metric, without a panic and
/// without marking anything unhealthy") is provable without a cluster and without a sleep:
///
/// * one metric increment, labelled with the fixed [`DriftFallbackReason`];
/// * the watch is parked for [`DriftWatcherConfig::fallback_cooldown`] (so it is retried later,
///   never in a hot loop);
/// * nothing else happens — no status patch, no readiness change, no error propagation. Model 1
///   polling is still running, which is what makes this a *fallback* rather than an outage.
pub fn record_fallback(
    reason: DriftFallbackReason,
    metrics: Option<&Metrics>,
    state: &mut FallbackState,
    now: Instant,
    config: &DriftWatcherConfig,
) -> WatchStep {
    if let Some(metrics) = metrics {
        metrics.record_drift_fallback(reason);
    }
    state.park(reason, now, config.fallback_cooldown);
    WatchStep::Restart
}

/// The metadata-only, label-scoped watch stream of one resolved target.
///
/// This is the **only** place a drift watch is built, so the `T18.2` trap guards are provable at the
/// wire instead of inferred from a helper:
///
/// * `Api<PartialObjectMeta<DynamicObject>>` — `Resource::metadata_api()` is `true` for
///   `PartialObjectMeta`, so kube asks for `application/json;as=PartialObjectMetadata;g=meta.k8s.io;
///   v=v1` on **every** request (`as=PartialObjectMetadataList` on the list). No `.spec`, no
///   `.status` and therefore no `Secret.data` byte ever leaves the API server.
/// * `watcher::Config::default().labels(..)` — the `ferriscd.io/managed-by=ferriscd` selector is
///   applied *server-side*, so a foreign object never crosses the wire at all.
///
/// `kube` 5.1's `metadata_watcher` is deprecated; this is its documented replacement (see the module
/// documentation for the deviation and why it changes nothing observable).
fn metadata_watch_stream(
    target: &WatchTarget,
) -> impl Stream<Item = Result<watcher::Event<PartialObjectMeta<DynamicObject>>, watcher::Error>> {
    let api: kube::Api<PartialObjectMeta<DynamicObject>> =
        kube::Api::all_with(target.client.clone(), &target.api_resource);
    watcher::watcher(api, watcher::Config::default().labels(&label_selector()))
}

/// Everything one watch task owns for its lifetime (`T18.2` finding C2).
///
/// `state` is shared with the supervisor: parking survives a respawn (a rebuilt cluster client, a
/// new served version) instead of resetting the cooldown, and `active` tells the supervisor whether
/// this task is streaming right now, so `ferriscd_drift_watcher_active_watches` never counts a parked
/// or restart-delayed watch as active.
struct WatchTask {
    /// The resolved `(cluster, group/kind)` this task watches.
    target: WatchTarget,
    /// Parking state, shared with the supervisor.
    state: SharedFallback,
    /// Whether the task is streaming right now.
    active: Arc<AtomicBool>,
    /// Cancels the task.
    stop: CancellationToken,
}

/// Runs one `(cluster, GVK)` metadata watch, restarting it and parking on permanent failures.
async fn run_one_watch(
    task: WatchTask,
    config: DriftWatcherConfig,
    router: Arc<Mutex<DriftRouter>>,
    channels: Arc<DriftTriggerChannels>,
    metrics: Option<Metrics>,
) {
    let WatchTask {
        target,
        state,
        active,
        stop,
    } = task;
    let clock = SystemDriftClock;
    loop {
        if stop.is_cancelled() {
            active.store(false, Ordering::Relaxed);
            return;
        }
        // A respawned watch inherits the parking state, so a permanent failure cannot become a retry
        // loop across supervisor refreshes. The wait is derived from `parked_until` (never a second
        // copy of the cooldown), so `FallbackState` is the single source of truth for "when may this
        // watch be retried".
        let cooldown = {
            let held = lock_recover(&state);
            held.parked_until()
                .map(|until| until.saturating_duration_since(clock.now()))
                .filter(|remaining| !remaining.is_zero())
        };
        if let Some(remaining) = cooldown {
            active.store(false, Ordering::Relaxed);
            tokio::select! {
                biased;
                () = stop.cancelled() => return,
                () = tokio::time::sleep(remaining) => {}
            }
            continue;
        }
        active.store(true, Ordering::Relaxed);
        let outcome = drive_metadata_stream(
            metadata_watch_stream(&target),
            &router,
            &target.cluster,
            &target.api_resource,
            &channels,
            &clock,
            &stop,
        )
        .await;
        // Whatever happens next, this task is not streaming between attempts: a restart-delayed or
        // parked watch must not be reported as an active watch.
        active.store(false, Ordering::Relaxed);
        match outcome {
            DriftStreamOutcome::Stopped => return,
            // `kube`'s watcher reconnects on its own, so an ended stream means the stream itself was
            // dropped (for example the API server closed the connection without an error). Restart
            // after a short pause rather than leaving a silently dead watch behind; `Stopped` (above)
            // is the only terminal outcome.
            DriftStreamOutcome::Ended => {
                tokio::select! {
                    biased;
                    () = stop.cancelled() => return,
                    () = tokio::time::sleep(ENDED_RESTART_DELAY) => {}
                }
            }
            DriftStreamOutcome::Fallback(reason) => {
                // ONE structured warning per parking episode (never one per event), the metric, and
                // a cooldown: Model 1 polling keeps detecting drift the whole time, so nothing is
                // marked unhealthy and nothing panics.
                tracing::warn!(
                    cluster = %target.cluster,
                    group = %target.api_resource.group,
                    kind = %target.api_resource.kind,
                    reason = reason.as_str(),
                    cooldown_seconds = config.fallback_cooldown.as_secs(),
                    "drift watcher falling back to periodic polling: the API server refused this \
                     metadata watch permanently"
                );
                let step = {
                    let mut held = lock_recover(&state);
                    record_fallback(reason, metrics.as_ref(), &mut held, clock.now(), &config)
                };
                if step == WatchStep::Stop {
                    return;
                }
                // The loop's parking branch performs the wait.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ferriscd_crd::annotations;
    use ferriscd_crd::status::{ApplicationStatus, InventoryEntry as StatusInventoryEntry};
    use kube::Resource as _;
    use kube::api::DynamicObject;
    use kube::core::{PartialObjectMetaExt, Status};
    use kube::runtime::reflector::ObjectRef;

    use super::*;

    /// The cluster every single-cluster fixture below lives in.
    ///
    /// The cluster dimension is exercised explicitly by the finding M-1 tests, which pass other
    /// names; everything else uses the destination a default `Application` has.
    const CLUSTER: &str = "in-cluster";

    /// `ObservedResource::from_metadata` bound to that cluster.
    fn observed(
        api_resource: &ApiResource,
        metadata: &ObjectMeta,
        deleted: bool,
    ) -> ObservedResource {
        ObservedResource::from_metadata(CLUSTER, api_resource, metadata, deleted)
    }

    /// The real `T18.1` label value of `team-a/payments` (the test's owning Application).
    fn hash_a() -> String {
        ferriscd_engine::inventory::app_hash("team-a", "payments")
    }

    /// A hash no watched Application claims.
    fn hash_unowned() -> String {
        ferriscd_engine::inventory::app_hash("team-nobody", "nothing")
    }

    // ------------------------------------------------------------------
    // Fixtures: a scripted metadata watch, an injected clock, a sink
    // ------------------------------------------------------------------

    fn metadata(
        name: &str,
        namespace: &str,
        generation: Option<i64>,
        resource_version: &str,
        app_hash: Option<&str>,
    ) -> ObjectMeta {
        let labels = app_hash.map(|hash| {
            std::collections::BTreeMap::from([(
                annotations::LABEL_APP_HASH.to_owned(),
                hash.to_owned(),
            )])
        });
        ObjectMeta {
            name: Some(name.to_owned()),
            namespace: Some(namespace.to_owned()),
            uid: Some(format!("uid-{name}")),
            generation,
            resource_version: Some(resource_version.to_owned()),
            labels,
            ..ObjectMeta::default()
        }
    }

    fn object(meta: ObjectMeta) -> PartialObjectMeta<DynamicObject> {
        // Exactly the shape a metadata-only watch decodes: `ObjectMeta` and nothing else.
        meta.into_response_partial::<DynamicObject>()
    }

    fn configmap(name: &str, namespace: &str, rv: &str, hash: &str) -> ObservedResource {
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        observed(
            &api_resource,
            &metadata(name, namespace, None, rv, Some(hash)),
            false,
        )
    }

    fn secret(name: &str, namespace: &str, rv: &str, hash: &str) -> ObservedResource {
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "Secret"));
        observed(
            &api_resource,
            &metadata(name, namespace, None, rv, Some(hash)),
            false,
        )
    }

    fn deployment(
        name: &str,
        namespace: &str,
        generation: i64,
        rv: &str,
        hash: &str,
    ) -> ObservedResource {
        let api_resource =
            ApiResource::from_gvk(&GroupVersionKind::gvk("apps", "v1", "Deployment"));
        observed(
            &api_resource,
            &metadata(name, namespace, Some(generation), rv, Some(hash)),
            false,
        )
    }

    fn app(namespace: &str, name: &str) -> Application {
        let spec = ferriscd_crd::ApplicationSpec {
            project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: ferriscd_crd::SourceSpec {
                git: Some(ferriscd_crd::GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "main".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: ferriscd_crd::RendererSpec::default(),
            },
            destination: ferriscd_crd::DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: ferriscd_crd::application::DEFAULT_REQUEUE_AFTER_SECONDS,
            revision_history_limit: ferriscd_crd::application::DEFAULT_REVISION_HISTORY_LIMIT,
        };
        let mut app = Application::new(name, spec);
        app.metadata.namespace = Some(namespace.to_owned());
        app
    }

    fn app_ref(namespace: &str, name: &str) -> ObjectRef<Application> {
        ObjectRef::new(name).within(namespace)
    }

    /// A router whose index claims `hash_a` for `team-a/payments` (and nothing else).
    fn router_with_app(
        config: &DriftWatcherConfig,
        apps: &[(&str, &str)],
        shard: Option<Sharding>,
    ) -> (DriftRouter, Arc<SelfEchoCache>) {
        let echo = Arc::new(config.echo_cache());
        let index = Arc::new(std::sync::RwLock::new(AppHashIndex::new()));
        let owned: Vec<Application> = apps.iter().map(|(ns, name)| app(ns, name)).collect();
        write_recover(&index).rebuild(owned.iter());
        let router = DriftRouter::new(config, shard, echo.clone(), index, None);
        (router, echo)
    }

    /// A sink built exactly like production: one bounded `mpsc` per scope.
    fn channels(
        capacity: usize,
        scopes: Vec<Option<String>>,
    ) -> (
        DriftTriggerChannels,
        Vec<tokio::sync::mpsc::Receiver<ObjectRef<Application>>>,
    ) {
        let mut senders = Vec::new();
        let mut receivers = Vec::new();
        for namespace in scopes {
            let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
            senders.push((namespace, sender));
            receivers.push(receiver);
        }
        (DriftTriggerChannels::new(senders, None), receivers)
    }

    /// An injected clock: the debounce/TTL/cooldown arithmetic runs in microseconds of test time.
    #[derive(Clone)]
    struct TestClock {
        now: Arc<Mutex<Instant>>,
    }

    impl TestClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn now(&self) -> Instant {
            *lock_recover(&self.now)
        }
    }

    impl DriftClock for TestClock {
        fn now(&self) -> Instant {
            TestClock::now(self)
        }

        fn sleep_until(&self, deadline: Option<Instant>) -> BoxFuture<'static, ()> {
            match deadline {
                // Advance the injected clock instead of waiting: no real sleep, no flake.
                Some(deadline) => {
                    let now = self.now.clone();
                    Box::pin(async move {
                        let mut held = lock_recover(&now);
                        if *held < deadline {
                            *held = deadline;
                        }
                    })
                }
                None => Box::pin(futures::future::pending()),
            }
        }
    }

    /// A `Duration` from whole seconds (readability for the injected-clock arithmetic).
    fn secs(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    fn scrape(metrics: &Metrics) -> String {
        metrics.encode().expect("the registry encodes")
    }

    // ------------------------------------------------------------------
    // Acceptance: self-echo suppression
    // ------------------------------------------------------------------

    /// **Verification bullet 1:** a `ConfigMap` self-apply does **not** re-trigger, while an external
    /// resource-version bump does.
    ///
    /// This is the trap the roadmap calls out: without the echo cache, `selfHeal: true` on a
    /// generation-less kind enters an infinite apply/watch feedback loop.
    #[test]
    fn a_configmap_self_apply_does_not_retrigger_but_an_external_bump_does() {
        let config = DriftWatcherConfig::from_flag(true);
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");

        // FerrisCD applies the object: the API server returns `resourceVersion: 10`.
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("settings", "payments", None, "10", Some(&hash_a())),
            now,
        );

        // The watcher then sees our own write echoed back.
        let decision = router.handle(&configmap("settings", "payments", "10", &hash_a()), now);
        assert_eq!(
            decision,
            DriftDecision::Suppressed(SelfEcho::Write),
            "the echo of our own apply must never arm a trigger"
        );
        assert_eq!(
            router.take_due(now + Duration::from_secs(10)),
            Vec::<ObjectRef<Application>>::new(),
            "a suppressed echo must not produce a reconcile"
        );

        // An out-of-band `kubectl edit` bumps the resource version.
        let decision = router.handle(&configmap("settings", "payments", "11", &hash_a()), now);
        assert_eq!(decision, DriftDecision::Debounced { apps: 1 });
        let due = router.take_due(now + config.debounce);
        assert_eq!(
            due,
            vec![app_ref("team-a", "payments")],
            "the external bump must trigger exactly the owning Application"
        );
    }

    /// **Verification bullet 2:** a status-only `Deployment` event (unchanged generation) is
    /// ignored, while a spec edit (generation bump) triggers.
    #[test]
    fn status_only_deployment_events_are_ignored_but_a_generation_bump_triggers() {
        let config = DriftWatcherConfig::from_flag(true);
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let key = ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api");

        // Our apply: generation 3, resourceVersion 100.
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("api", "payments", Some(3), "100", Some(&hash_a())),
            now,
        );

        // A `/status` write: same generation, new resourceVersion. It must be ignored, because the
        // object's spec did not change.
        assert_eq!(
            router.handle(&deployment("api", "payments", 3, "101", &hash_a()), now),
            DriftDecision::Suppressed(SelfEcho::UnchangedGeneration),
            "a status-only event is not drift"
        );

        // A `kubectl edit` of the spec bumps the generation.
        assert_eq!(
            router.handle(&deployment("api", "payments", 4, "102", &hash_a()), now),
            DriftDecision::Debounced { apps: 1 }
        );
        assert_eq!(
            router.take_due(now + config.debounce),
            vec![app_ref("team-a", "payments")]
        );
    }

    /// **Trap guard:** the echo cache expires (TTL) and is bounded (cap). An expired entry is not
    /// evidence of anything — the event triggers and the entry is evicted — and a burst of writes
    /// beyond the cap evicts the oldest instead of growing without bound.
    #[test]
    fn an_expired_or_out_of_order_echo_never_suppresses_a_real_change() {
        let config = DriftWatcherConfig::from_flag(true).with_echo(Duration::from_secs(60), 2);
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let key = ResourceKey::new("", "Secret", Some("payments".to_owned()), "creds");

        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("creds", "payments", None, "5", Some(&hash_a())),
            now,
        );

        // Inside the TTL: suppressed.
        assert!(matches!(
            router.handle(&secret("creds", "payments", "5", &hash_a()), now),
            DriftDecision::Suppressed(_)
        ));

        // Exactly at the TTL: the entry has expired, so the same resource version now triggers —
        // a stale record may cost one reconcile, never hide a drift.
        let expired = now + Duration::from_secs(60);
        assert_eq!(
            router.handle(&secret("creds", "payments", "5", &hash_a()), expired),
            DriftDecision::Debounced { apps: 1 },
            "an expired echo entry must not suppress anything"
        );
        assert!(
            echo.suppresses(
                &MetadataObservation {
                    cluster: CLUSTER,
                    key: &key,
                    uid: None,
                    generation: None,
                    resource_version: Some("5"),
                    deleted: false,
                },
                expired,
            )
            .is_none(),
            "the expired entry is treated as absent"
        );

        // Out-of-order: our *latest* write is resourceVersion 20, and an older echo (10) arrives
        // afterwards. Resource versions are opaque, so equality is the only sound comparison; the
        // stale event is therefore treated as external (one harmless no-op reconcile) rather than
        // risking a silently ignored edit.
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("creds", "payments", None, "20", Some(&hash_a())),
            expired,
        );
        assert_eq!(
            router.handle(&secret("creds", "payments", "10", &hash_a()), expired),
            DriftDecision::Debounced { apps: 1 },
            "only the latest recorded write is provably our own"
        );
        assert!(
            matches!(
                router.handle(&secret("creds", "payments", "20", &hash_a()), expired),
                DriftDecision::Suppressed(SelfEcho::Write)
            ),
            "the latest write is still suppressed"
        );

        // Bounded: the third distinct key pushes the oldest entries out.
        for name in ["one", "two", "three"] {
            let other = ResourceKey::new("", "Secret", Some("payments".to_owned()), name);
            echo.record_apply(
                CLUSTER,
                &other,
                &metadata(name, "payments", None, "1", Some(&hash_a())),
                expired,
            );
        }
        assert_eq!(
            echo.len(),
            2,
            "the self-echo cache must stay at its cap, never grow with the fleet"
        );
    }

    /// **Finding C1:** a *recorded prune* suppresses the `Delete` event FerrisCD caused itself.
    #[test]
    fn a_recorded_prune_suppresses_the_delete_event_it_caused() {
        let config = DriftWatcherConfig::from_flag(true);
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");

        // FerrisCD applied the object at resourceVersion 31 and then pruned it.
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("settings", "payments", None, "31", Some(&hash_a())),
            now,
        );
        echo.record_prune(CLUSTER, &key, now);
        let own = observed(
            &api_resource,
            &metadata("settings", "payments", None, "31", Some(&hash_a())),
            true,
        );
        assert_eq!(
            router.handle(&own, now),
            DriftDecision::Suppressed(SelfEcho::Prune),
            "the delete FerrisCD issued itself is not drift"
        );
        assert_eq!(router.pending(), 0, "a suppressed prune arms nothing");
    }

    /// **Finding C1 (the regression this test exists for):** a `Delete` event repeats the object's
    /// **last written** resource version, so a delete of an object FerrisCD *just applied* looks
    /// exactly like the echo of our own write.
    ///
    /// Suppressing that match would hide an out-of-band `kubectl delete` **forever**: the object is
    /// gone, so no later event can correct the mistake. Only a prune marker may suppress a delete.
    #[test]
    fn an_external_delete_of_a_just_applied_object_triggers() {
        let config = DriftWatcherConfig::from_flag(true);
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let configmap_api = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let deployment_api =
            ApiResource::from_gvk(&GroupVersionKind::gvk("apps", "v1", "Deployment"));
        let a_second_later = secs(1);

        // Generation-less kind: `ConfigMap` applied at resourceVersion 41.
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("settings", "payments", None, "41", Some(&hash_a())),
            now,
        );
        // `kubectl delete configmap settings` one second later: the delete event carries the same
        // uid and the same resource version, and there is no prune marker.
        let deleted = observed(
            &configmap_api,
            &metadata("settings", "payments", None, "41", Some(&hash_a())),
            true,
        );
        assert_eq!(
            router.handle(&deleted, now + a_second_later),
            DriftDecision::Debounced { apps: 1 },
            "an external delete of the object we just applied must trigger, not be suppressed as \
             our own write"
        );
        assert_eq!(
            router.take_due(now + a_second_later + config.debounce),
            vec![app_ref("team-a", "payments")],
            "the external delete must reach the owning Application"
        );

        // Generation-bearing kind: `Deployment` applied at generation 3 / resourceVersion 51, then
        // deleted externally. `(uid, generation)` matches our apply exactly.
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let key = ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api");
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("api", "payments", Some(3), "51", Some(&hash_a())),
            now,
        );
        let deleted = observed(
            &deployment_api,
            &metadata("api", "payments", Some(3), "51", Some(&hash_a())),
            true,
        );
        assert_eq!(
            router.handle(&deleted, now + a_second_later),
            DriftDecision::Debounced { apps: 1 },
            "a delete is never an unchanged-generation echo, whatever the generation says"
        );

        // Control: a delete with no recorded write at all is external drift too, so the assertion
        // above is not a property of "every delete triggers" but of "no marker, so it is drift".
        let (mut router, _echo) = router_with_app(&config, &[("team-a", "payments")], None);
        assert_eq!(
            router.handle(
                &observed(
                    &configmap_api,
                    &metadata("settings", "payments", None, "99", Some(&hash_a())),
                    true,
                ),
                now,
            ),
            DriftDecision::Debounced { apps: 1 }
        );
    }

    /// **Finding M-1:** the echo record is keyed by `(destination cluster, GKNN)`, so a prune marker
    /// or an apply echo recorded for cluster A never suppresses an event from cluster B.
    ///
    /// `ResourceKey` is deliberately version-agnostic (that is what keeps an API upgrade from
    /// self-pruning), and it is equally cluster-agnostic: `team-a/settings` exists in every cluster.
    /// Without the cluster in the echo identity, a prune in cluster A would hide a real out-of-band
    /// `kubectl delete` of the same GKNN in cluster B for the whole TTL — and a deleted object is
    /// never corrected by a later event.
    #[test]
    fn an_echo_recorded_for_one_cluster_never_suppresses_another_clusters_event() {
        const CLUSTER_A: &str = "cluster-a";
        const CLUSTER_B: &str = "cluster-b";
        let config = DriftWatcherConfig::from_flag(true);
        let now = Instant::now();
        let hash = hash_a();
        let configmap_api = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let deployment_api =
            ApiResource::from_gvk(&GroupVersionKind::gvk("apps", "v1", "Deployment"));

        /// The same observation, reported by another cluster.
        fn in_cluster(
            cluster: &str,
            api_resource: &ApiResource,
            metadata: &ObjectMeta,
            deleted: bool,
        ) -> ObservedResource {
            ObservedResource::from_metadata(cluster, api_resource, metadata, deleted)
        }

        // --- a prune marker in A says nothing about a delete in B ---------------------------
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        let settings = metadata("settings", "payments", None, "31", Some(&hash));
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        echo.record_apply(CLUSTER_A, &key, &settings, now);
        echo.record_prune(CLUSTER_A, &key, now);

        assert_eq!(
            router.handle(&in_cluster(CLUSTER_B, &configmap_api, &settings, true), now),
            DriftDecision::Debounced { apps: 1 },
            "a prune FerrisCD issued in cluster A must not suppress cluster B's delete"
        );
        assert_eq!(
            router.take_due(now + config.debounce),
            vec![app_ref("team-a", "payments")],
            "the out-of-band delete in cluster B must reach its Application"
        );
        // …and the cross-cluster event did not consume A's one-shot marker (finding M-2): the
        // delete FerrisCD itself issued in A is still recognised as ours.
        assert_eq!(
            router.handle(&in_cluster(CLUSTER_A, &configmap_api, &settings, true), now),
            DriftDecision::Suppressed(SelfEcho::Prune),
            "the marker must still be there for the cluster it was recorded for"
        );

        // --- an apply echo in A says nothing about a write in B -----------------------------
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let applied = metadata("settings", "payments", None, "41", Some(&hash));
        echo.record_apply(CLUSTER_A, &key, &applied, now);
        assert_eq!(
            router.handle(&in_cluster(CLUSTER_B, &configmap_api, &applied, false), now),
            DriftDecision::Debounced { apps: 1 },
            "the same resourceVersion in another cluster is an external write, not our echo"
        );
        assert_eq!(
            router.handle(&in_cluster(CLUSTER_A, &configmap_api, &applied, false), now),
            DriftDecision::Suppressed(SelfEcho::Write),
            "our own echo in the cluster we wrote to is still suppressed"
        );

        // Generation-bearing kinds carry the cluster too: the same `(uid, generation)` in another
        // cluster is a status write there, not evidence about ours.
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let deployment = ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api");
        echo.record_apply(
            CLUSTER_A,
            &deployment,
            &metadata("api", "payments", Some(3), "51", Some(&hash)),
            now,
        );
        let status_only = metadata("api", "payments", Some(3), "52", Some(&hash));
        assert_eq!(
            router.handle(
                &in_cluster(CLUSTER_B, &deployment_api, &status_only, false),
                now
            ),
            DriftDecision::Debounced { apps: 1 },
            "the uid/generation pair of another cluster's object is a different object"
        );
        assert_eq!(
            router.handle(
                &in_cluster(CLUSTER_A, &deployment_api, &status_only, false),
                now
            ),
            DriftDecision::Suppressed(SelfEcho::UnchangedGeneration)
        );

        // --- the reverse direction: the pair is the key, not "the cluster is ignored" --------
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        echo.record_prune(CLUSTER_B, &deployment, now);
        assert_eq!(
            router.handle(
                &in_cluster(CLUSTER, &deployment_api, &status_only, true),
                now
            ),
            DriftDecision::Debounced { apps: 1 },
            "a marker recorded for cluster B cannot suppress the in-cluster delete"
        );
        assert_eq!(
            router.handle(
                &in_cluster(CLUSTER_B, &deployment_api, &status_only, true),
                now
            ),
            DriftDecision::Suppressed(SelfEcho::Prune)
        );
    }

    /// **Finding M (the echo half):** record and lookup agree on the cluster **spelling**.
    ///
    /// `SyncExecutor` records whatever `spec.destination.cluster` literally says, while the watch
    /// gets its cluster from a plan that is trimmed (and from `ClusterManager::get`, which trims
    /// too). Without normalizing at the `EchoKey`, a padded `"  in-cluster  "` would record under
    /// one spelling and look up under another — reopening the apply → watch → apply loop the cache
    /// exists to break, for exactly the `Application`s whose destination is padded.
    #[test]
    fn a_padded_destination_cluster_echoes_under_the_same_identity() {
        let config = DriftWatcherConfig::from_flag(true);
        let now = Instant::now();
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        let settings = metadata("settings", "payments", None, "71", Some(&hash_a()));

        // Recorded with the raw spec spelling, observed under the trimmed watch identity.
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        echo.record_apply("  in-cluster  ", &key, &settings, now);
        assert_eq!(
            router.handle(&configmap("settings", "payments", "71", &hash_a()), now),
            DriftDecision::Suppressed(SelfEcho::Write),
            "a padded destination's own apply must not arm a trigger"
        );
        assert_eq!(router.pending(), 0);

        // The reverse direction: the record is plain, the observation padded (a target resolved
        // before the plan normalized, or a `Delete` reported with the spec's spelling).
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        echo.record_prune(CLUSTER, &key, now);
        let padded = ObservedResource::from_metadata(
            "  in-cluster  ",
            &api_resource,
            &metadata("settings", "payments", None, "71", Some(&hash_a())),
            true,
        );
        assert_eq!(
            router.handle(&padded, now),
            DriftDecision::Suppressed(SelfEcho::Prune),
            "the marker FerrisCD wrote for the delete it issued must match the padded spelling"
        );

        // A *different* cluster is still a different owner: trimming is not "ignore the cluster".
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        echo.record_prune("  edge  ", &key, now);
        let delete_in_cluster = ObservedResource::from_metadata(
            CLUSTER,
            &api_resource,
            &metadata("settings", "payments", None, "71", Some(&hash_a())),
            true,
        );
        assert_eq!(
            router.handle(&delete_in_cluster, now),
            DriftDecision::Debounced { apps: 1 },
            "a marker trimmed to another cluster must not suppress the in-cluster delete"
        );
    }

    /// **Finding M-2:** a prune marker suppresses exactly **one** `Delete` event.
    ///
    /// A marker that survived its own event would absorb the *next* delete of the same key — which
    /// is the one it must never hide: the object is pruned, re-added to Git, re-created and then
    /// deleted out of band all within one TTL, and a durable marker would silently swallow that
    /// last, external delete forever.
    #[test]
    fn a_prune_marker_suppresses_exactly_one_delete() {
        let config = DriftWatcherConfig::from_flag(true);
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        let hash = hash_a();
        let deleted = observed(
            &api_resource,
            &metadata("settings", "payments", None, "61", Some(&hash)),
            true,
        );

        // FerrisCD prunes `payments/settings`.
        echo.record_prune(CLUSTER, &key, now);

        // The first `Delete` is the one the marker was written for.
        assert_eq!(
            router.handle(&deleted, now),
            DriftDecision::Suppressed(SelfEcho::Prune)
        );
        assert_eq!(router.pending(), 0, "a suppressed prune arms nothing");
        assert!(
            echo.is_empty(),
            "the marker is consumed by the event it suppressed, not kept for the TTL"
        );

        // A second delete of the same key: the object came back (a re-add to Git, a `Replace`) and
        // somebody else deleted it. Nothing may absorb that.
        assert_eq!(
            router.handle(&deleted, now + secs(1)),
            DriftDecision::Debounced { apps: 1 },
            "one marker suppresses one delete, never the next one"
        );
        assert_eq!(
            router.take_due(now + secs(1) + config.debounce),
            vec![app_ref("team-a", "payments")]
        );
        assert!(
            echo.suppresses(
                &MetadataObservation {
                    cluster: CLUSTER,
                    key: &key,
                    uid: None,
                    generation: None,
                    resource_version: Some("61"),
                    deleted: true,
                },
                now + secs(2),
            )
            .is_none(),
            "a delete with no live marker is drift, however recently FerrisCD pruned that key"
        );

        // A later prune re-arms the marker: the contract is one marker per delete, not one per key.
        echo.record_prune(CLUSTER, &key, now + secs(3));
        assert_eq!(
            router.handle(&deleted, now + secs(3)),
            DriftDecision::Suppressed(SelfEcho::Prune),
            "the next delete FerrisCD issues gets its own marker"
        );
    }

    /// **Finding M3:** a suppressed `/status`-only event also refreshes the baseline, so a
    /// long-lived object whose status churns never loses its entry to the TTL (which would make the
    /// next status-only event trigger a spurious reconcile).
    #[test]
    fn a_status_only_event_refreshes_the_echo_ttl() {
        let config = DriftWatcherConfig::from_flag(true).with_echo(Duration::from_secs(60), 16);
        let (mut router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let start = Instant::now();
        let key = ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api");
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("api", "payments", Some(3), "100", Some(&hash_a())),
            start,
        );

        // 50 s in: a `/status` write. Suppressed, and it re-baselines the entry.
        assert_eq!(
            router.handle(
                &deployment("api", "payments", 3, "101", &hash_a()),
                start + secs(50)
            ),
            DriftDecision::Suppressed(SelfEcho::UnchangedGeneration)
        );
        // 80 s after the *apply* (but 30 s after the refresh): still suppressed. Without the
        // refresh the TTL would have expired 20 s ago and this event would trigger.
        assert_eq!(
            router.handle(
                &deployment("api", "payments", 3, "102", &hash_a()),
                start + secs(80)
            ),
            DriftDecision::Suppressed(SelfEcho::UnchangedGeneration),
            "a status-only event must refresh the entry instead of letting it expire"
        );
        // A real edit still triggers, whatever the refreshed baseline says.
        assert_eq!(
            router.handle(
                &deployment("api", "payments", 4, "103", &hash_a()),
                start + secs(81)
            ),
            DriftDecision::Debounced { apps: 1 }
        );
        // And the TTL still expires: 61 s after the last refresh the entry is gone, so even a
        // status-only event is treated as unprovable (one harmless no-op reconcile).
        assert_eq!(
            router.handle(
                &deployment("api", "payments", 4, "103", &hash_a()),
                start + secs(142)
            ),
            DriftDecision::Debounced { apps: 1 }
        );
    }

    /// **Finding M1:** the sweep is amortized — expired entries are *not* reclaimed by every write
    /// (that would be an `O(n)` pass on the sync path), but the cache never exceeds its cap and a
    /// full sweep does reclaim them.
    #[test]
    fn the_echo_cache_sweeps_amortized_and_stays_at_its_cap() {
        let cache = SelfEchoCache::new(Duration::from_secs(60), 4);
        let start = Instant::now();
        for name in ["a", "b", "c"] {
            let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), name);
            cache.record_apply(
                CLUSTER,
                &key,
                &metadata(name, "payments", None, "1", Some(&hash_a())),
                start,
            );
        }
        assert_eq!(cache.len(), 3);

        // One write after the TTL, still under the cap and under the sweep interval: nothing is
        // reclaimed yet, which is what makes recording `O(1)` instead of `O(n)`.
        let later = start + Duration::from_secs(61);
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "d");
        cache.record_apply(
            CLUSTER,
            &key,
            &metadata("d", "payments", None, "2", Some(&hash_a())),
            later,
        );
        assert_eq!(
            cache.len(),
            4,
            "recording must not sweep on every write (the expired entries are still here)"
        );
        // …and the stale entries still cannot suppress anything: the TTL is checked on lookup.
        let stale = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "a");
        assert!(
            cache
                .suppresses(
                    &MetadataObservation {
                        cluster: CLUSTER,
                        key: &stale,
                        uid: Some("uid-a"),
                        generation: None,
                        resource_version: Some("1"),
                        deleted: false,
                    },
                    later,
                )
                .is_none(),
            "an expired entry never suppresses, swept or not"
        );

        // The amortized sweep still runs: `SWEEP_INTERVAL` writes reclaim what the TTL dropped.
        for index in 0..SWEEP_INTERVAL {
            let name = format!("key-{index}");
            let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), &name);
            cache.record_apply(
                CLUSTER,
                &key,
                &metadata(&name, "payments", None, "3", Some(&hash_a())),
                later,
            );
        }
        assert!(
            cache.len() <= 4,
            "the cache must never grow past its cap, got {} entries",
            cache.len()
        );
    }

    // ------------------------------------------------------------------
    // Acceptance: sharding, scope routing, non-blocking delivery
    // ------------------------------------------------------------------

    /// **Verification bullet 4:** the shard filter drops triggers for `Application`s this replica
    /// does not own, and it compares exactly `Sharding::owns(namespace, name)`.
    #[test]
    fn the_shard_filter_drops_triggers_for_non_owned_applications() {
        let config = DriftWatcherConfig::from_flag(true);
        let shard = Sharding::new(0, 2).expect("valid shard");
        let namespace = "test-shard-scope";
        let (owned, foreign) = (0..1_000)
            .map(|index| format!("app-{index}"))
            .find_map(|name| {
                let shard_of_name = crate::sharding::shard_of(namespace, &name, 2);
                (shard_of_name == 0).then_some(name)
            })
            .and_then(|owned| {
                (0..1_000)
                    .map(|index| format!("app-{index}"))
                    .find(|name| crate::sharding::shard_of(namespace, name, 2) == 1)
                    .map(|foreign| (owned, foreign))
            })
            .expect("both shards own at least one of the first 1000 names");

        // The foreign Application's hash: only *it* claims the object.
        let foreign_hash = ferriscd_engine::inventory::app_hash(namespace, &foreign);
        let (mut router, _echo) = router_with_app(&config, &[(namespace, &foreign)], Some(shard));
        let now = Instant::now();
        assert_eq!(
            router.handle(&configmap("settings", "payments", "1", &foreign_hash), now),
            DriftDecision::Filtered,
            "another shard's Application must never be triggered"
        );
        assert!(router.pending() == 0);
        assert!(
            router.take_due(now + Duration::from_secs(60)).is_empty(),
            "a filtered event yields no reconcile at all"
        );

        // The owned one is untouched by the filter.
        let owned_hash = ferriscd_engine::inventory::app_hash(namespace, &owned);
        let (mut router, _echo) = router_with_app(&config, &[(namespace, &owned)], Some(shard));
        assert_eq!(
            router.handle(&configmap("settings", "payments", "1", &owned_hash), now),
            DriftDecision::Debounced { apps: 1 }
        );
        assert_eq!(
            router.take_due(now + config.debounce),
            vec![app_ref(namespace, &owned)]
        );
    }

    /// An object with no `ferriscd.io/app-hash`, or one no watched `Application` claims, is reported
    /// as unmapped instead of triggering the whole fleet.
    #[test]
    fn an_unmapped_object_never_triggers_anything() {
        let config = DriftWatcherConfig::from_flag(true);
        let (mut router, _echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();

        assert_eq!(
            router.handle(
                &configmap("settings", "payments", "1", &hash_unowned()),
                now
            ),
            DriftDecision::Unmapped,
            "no Application claims this hash"
        );

        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let unlabelled = observed(
            &api_resource,
            &metadata("settings", "payments", None, "2", None),
            false,
        );
        assert_eq!(router.handle(&unlabelled, now), DriftDecision::Unmapped);

        // An event without a resourceVersion cannot be compared to anything: ignored, not guessed.
        let versionless = ObservedResource {
            cluster: CLUSTER.to_owned(),
            key: ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings"),
            uid: None,
            generation: None,
            resource_version: None,
            app_hash: Some(hash_a()),
            deleted: false,
        };
        assert_eq!(router.handle(&versionless, now), DriftDecision::Ignored);
        assert_eq!(router.pending(), 0);
    }

    /// The app-hash index is built from the `Application`s this replica watches: `ns-a/app` and
    /// `ns-b/app` (`T18.1`'s finding M5) resolve to different entries.
    #[test]
    fn the_app_hash_index_keeps_namespaces_apart() {
        let mut index = AppHashIndex::new();
        let team_a = app("team-a", "payments");
        let team_b = app("team-b", "payments");
        index.rebuild([&team_a, &team_b]);

        let hash_a = ferriscd_engine::inventory::app_hash("team-a", "payments");
        let hash_b = ferriscd_engine::inventory::app_hash("team-b", "payments");
        assert_ne!(hash_a, hash_b);
        assert_eq!(index.lookup(&hash_a), &[app_ref("team-a", "payments")]);
        assert_eq!(index.lookup(&hash_b), &[app_ref("team-b", "payments")]);
        assert_eq!(index.len(), 2);
        assert!(
            index.lookup("0000000000000000").is_empty(),
            "an unknown hash maps to nothing"
        );
    }

    /// **Trap guard:** a saturated trigger channel must not block the watch loop. `try_send` reports
    /// `Full` synchronously, the trigger is dropped, and the periodic reconcile still converges the
    /// `Application`.
    #[test]
    fn a_full_trigger_channel_drops_instead_of_blocking() {
        let metrics = Metrics::new();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let channels = DriftTriggerChannels::new(
            vec![(Some("team-a".to_owned()), sender)],
            Some(metrics.clone()),
        );

        assert_eq!(
            channels.try_send(&app_ref("team-a", "payments")),
            TriggerDelivery::Enqueued
        );
        // Nothing is consuming: the queue is full, and the call still returns immediately.
        assert_eq!(
            channels.try_send(&app_ref("team-a", "second")),
            TriggerDelivery::Full,
            "the watch loop must never block on a full controller queue"
        );
        assert_eq!(
            channels.try_send(&app_ref("other-ns", "third")),
            TriggerDelivery::NoScope,
            "an Application outside every watched scope is never handed to the wrong controller"
        );
        assert_eq!(
            receiver.try_recv().expect("the first trigger is queued"),
            app_ref("team-a", "payments")
        );
        assert!(
            receiver.try_recv().is_err(),
            "a dropped trigger is not silently retried"
        );
        // The drop is observable on the fixed outcome family (never a new label).
        let body = scrape(&metrics);
        assert!(
            body.contains("ferriscd_drift_watcher_events_total{outcome=\"dropped\"} 2"),
            "both drops must be counted, distinctly from 'ignored': {body}"
        );
        // **Finding M2:** the trigger counter tracks what the controller actually received, so the
        // two dropped deliveries must not inflate it.
        assert!(
            body.contains("ferriscd_drift_watcher_triggers_total 1"),
            "only an enqueued trigger counts (finding M2): {body}"
        );
    }

    /// A trigger for a tenant namespace goes to that scope; the cluster-wide scope is the fallback.
    #[test]
    fn triggers_route_to_the_scope_that_watches_the_application() {
        let (channels, mut receivers) = channels(4, vec![Some("team-a".to_owned()), None]);
        assert_eq!(
            channels.try_send(&app_ref("team-a", "payments")),
            TriggerDelivery::Enqueued
        );
        assert_eq!(
            channels.try_send(&app_ref("team-z", "unknown")),
            TriggerDelivery::Enqueued
        );
        let exact_scope = receivers[0]
            .try_recv()
            .expect("the tenant scope gets its own trigger");
        assert_eq!(exact_scope.namespace.as_deref(), Some("team-a"));
        assert_eq!(exact_scope.name, "payments");
        assert!(
            receivers[0].try_recv().is_err(),
            "the cluster-wide trigger must not be duplicated into the tenant scope"
        );
        let wide_scope = receivers[1]
            .try_recv()
            .expect("the `*` scope is the fallback");
        assert_eq!(wide_scope.namespace.as_deref(), Some("team-z"));
        assert_eq!(wide_scope.name, "unknown");
    }

    // ------------------------------------------------------------------
    // Acceptance: debounce / coalescing
    // ------------------------------------------------------------------

    /// **Verification bullet 5:** a burst of 50 events for one `Application` coalesces into exactly
    /// one trigger, and a continuously noisy object is still capped by the max-wait ceiling.
    #[test]
    fn fifty_events_coalesce_into_one_trigger() {
        let config = DriftWatcherConfig::from_flag(true);
        let (mut router, _echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let start = Instant::now();

        for index in 0..50_u64 {
            let now = start + Duration::from_millis(index * 20);
            let decision = router.handle(
                &configmap("settings", "payments", &format!("{}", index + 1), &hash_a()),
                now,
            );
            assert!(
                matches!(decision, DriftDecision::Debounced { apps: 1 }),
                "event {index} must arm the debouncer: {decision:?}"
            );
        }

        // The last event landed at +980ms: the trailing window closes at +2.98s.
        assert!(
            router
                .take_due(start + Duration::from_millis(2_900))
                .is_empty(),
            "no trigger may fire inside the trailing window"
        );
        let due = router.take_due(start + Duration::from_millis(2_980));
        assert_eq!(
            due,
            vec![app_ref("team-a", "payments")],
            "the whole 50-event burst is one reconcile"
        );
        assert!(router.take_due(start + Duration::from_secs(60)).is_empty());
    }

    /// The max-wait ceiling: an object edited faster than the debounce window still triggers every
    /// `max_debounce`, instead of being starved forever.
    #[test]
    fn a_continuously_changing_object_is_capped_by_the_max_wait_ceiling() {
        let config = DriftWatcherConfig::from_flag(true);
        let mut debouncer = DriftDebouncer::new(config.debounce, config.max_debounce);
        let start = Instant::now();
        let reference = app_ref("team-a", "payments");

        for index in 0..100_u64 {
            debouncer.push(
                reference.clone(),
                start + Duration::from_millis(index * 100),
            );
        }

        // Pushed every 100ms from +0s to +9.9s: the trailing window never closes, but the ceiling
        // (first + 5s) does.
        assert!(
            debouncer
                .take_due(start + Duration::from_millis(4_999))
                .is_empty(),
            "before the ceiling nothing is due"
        );
        assert_eq!(
            debouncer.take_due(start + Duration::from_secs(5)),
            vec![reference],
            "the max-wait ceiling bounds the latency of a noisy object"
        );
    }

    /// The driver flushes a pending debounce entry when a watch ends, so the last event of a dying
    /// watch is not lost.
    #[tokio::test]
    async fn a_watch_that_ends_flushes_its_pending_triggers() {
        let config = DriftWatcherConfig::from_flag(true);
        let (router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("settings", "payments", None, "1", Some(&hash_a())),
            now,
        );
        let (channels, mut receivers) = channels(8, vec![Some("team-a".to_owned())]);
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let clock = TestClock::new();
        let stream = futures::stream::iter(vec![
            Ok(watcher::Event::Init),
            Ok(watcher::Event::InitApply(object(metadata(
                "settings",
                "payments",
                None,
                "1",
                Some(&hash_a()),
            )))),
            Ok(watcher::Event::InitDone),
            Ok(watcher::Event::Apply(object(metadata(
                "settings",
                "payments",
                None,
                "2",
                Some(&hash_a()),
            )))),
        ]);

        let outcome = drive_metadata_stream(
            stream,
            &Mutex::new(router),
            CLUSTER,
            &api_resource,
            &channels,
            &clock,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(outcome, DriftStreamOutcome::Ended);
        assert_eq!(
            receivers[0]
                .try_recv()
                .expect("the pending trigger is flushed when the watch ends")
                .name,
            "payments"
        );
    }

    // ------------------------------------------------------------------
    // Acceptance: 403 fallback
    // ------------------------------------------------------------------

    fn api_error(code: u16) -> watcher::Error {
        watcher::Error::InitialListFailed(kube::Error::Api(Box::new(Status {
            code,
            message: "denied".to_owned(),
            reason: "Forbidden".to_owned(),
            ..Status::default()
        })))
    }

    /// **Verification bullet 3:** `403 Forbidden` ends the stream with a fallback (not an error, not a
    /// panic), increments `ferriscd_drift_watcher_fallback_total{reason="forbidden"}` exactly once,
    /// parks the watch for the cooldown, and leaves everything else alone.
    #[tokio::test]
    async fn a_403_parks_the_watch_and_increments_the_metric_without_failing_anything() {
        let config = DriftWatcherConfig::from_flag(true);
        let metrics = Metrics::new();
        let (router, _echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let (channels, _receivers) = channels(8, vec![Some("team-a".to_owned())]);
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let clock = TestClock::new();
        let stream = futures::stream::iter(vec![Ok(watcher::Event::Init), Err(api_error(403))]);

        let outcome = drive_metadata_stream(
            stream,
            &Mutex::new(router),
            CLUSTER,
            &api_resource,
            &channels,
            &clock,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(
            outcome,
            DriftStreamOutcome::Fallback(DriftFallbackReason::Forbidden),
            "a permanent API error is a fallback outcome, never a propagated failure"
        );

        // The supervisor's reaction: one metric increment and a 15-minute park.
        let mut state = FallbackState::default();
        let now = clock.now();
        assert_eq!(
            record_fallback(
                DriftFallbackReason::Forbidden,
                Some(&metrics),
                &mut state,
                now,
                &config
            ),
            WatchStep::Restart,
            "the watch is retried after the cooldown, never abandoned for the process lifetime"
        );
        assert!(state.is_parked(now + Duration::from_secs(60)));
        assert!(state.is_parked(now + FALLBACK_COOLDOWN - Duration::from_secs(1)));
        assert!(
            !state.is_parked(now + FALLBACK_COOLDOWN),
            "the park ends exactly at the cooldown"
        );
        assert_eq!(state.reason(), Some(DriftFallbackReason::Forbidden));
        let body = scrape(&metrics);
        assert!(
            body.contains("ferriscd_drift_watcher_fallback_total{reason=\"forbidden\"} 1"),
            "the fallback must be counted once, with the fixed reason label: {body}"
        );
        assert!(
            !body.contains("reason=\"not_found\""),
            "only the observed reason is incremented: {body}"
        );

        // **No `Ready=False`:** the fallback touches nothing but its own metric and parking state.
        // Readiness is captured before and after on purpose, so a future change that starts marking
        // the control plane unhealthy here fails this test. All three `T17.1` startup gates are
        // satisfied first, so the baseline really is "ready" and the comparison is meaningful.
        let readiness = crate::ControlPlaneReadiness::new();
        readiness.mark_controllers_ready();
        readiness.mark_clusters_seeded();
        readiness.mark_rbac_loaded();
        let before = (readiness.is_ready(), readiness.reason());
        let mut state = FallbackState::default();
        let _ = record_fallback(
            DriftFallbackReason::NotFound,
            Some(&metrics),
            &mut state,
            now,
            &config,
        );
        assert_eq!(
            (readiness.is_ready(), readiness.reason()),
            before,
            "a permanent watch failure must never change control-plane readiness"
        );
        assert!(before.0, "the fixture is ready before the fallback");
        assert_eq!(before.1, None, "a ready replica explains nothing");
    }

    /// Every permanent code maps to its fixed label value; a transient one never parks a watcher.
    #[test]
    fn only_the_three_permanent_codes_fall_back() {
        assert_eq!(
            DriftFallbackReason::of_watch_error(&api_error(403)),
            Some(DriftFallbackReason::Forbidden)
        );
        assert_eq!(
            DriftFallbackReason::of_watch_error(&api_error(404)),
            Some(DriftFallbackReason::NotFound)
        );
        assert_eq!(
            DriftFallbackReason::of_watch_error(&api_error(405)),
            Some(DriftFallbackReason::MethodNotAllowed)
        );
        for transient in [0, 401, 409, 410, 429, 500, 503] {
            assert_eq!(
                DriftFallbackReason::of_watch_error(&api_error(transient)),
                None,
                "{transient} must not park a watcher for fifteen minutes"
            );
        }
        assert_eq!(
            DriftFallbackReason::of_watch_error(&watcher::Error::NoResourceVersion),
            None
        );
        // The label set is exactly the three documented values.
        let labels: Vec<&str> = [
            DriftFallbackReason::Forbidden,
            DriftFallbackReason::NotFound,
            DriftFallbackReason::MethodNotAllowed,
        ]
        .iter()
        .map(|reason| reason.as_str())
        .collect();
        assert_eq!(labels, crate::metrics::DRIFT_FALLBACK_REASONS.to_vec());
    }

    /// A transient watch error does not end the stream: the driver keeps consuming events (kube's
    /// own watch backoff is what retries the connection).
    #[tokio::test]
    async fn a_transient_watch_error_does_not_end_the_watch() {
        let config = DriftWatcherConfig::from_flag(true);
        let (router, echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let now = Instant::now();
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        echo.record_apply(
            CLUSTER,
            &key,
            &metadata("settings", "payments", None, "1", Some(&hash_a())),
            now,
        );
        let (channels, mut receivers) = channels(8, vec![Some("team-a".to_owned())]);
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let clock = TestClock::new();
        let stream = futures::stream::iter(vec![
            Err(api_error(500)),
            Ok(watcher::Event::Apply(object(metadata(
                "settings",
                "payments",
                None,
                "2",
                Some(&hash_a()),
            )))),
        ]);

        let outcome = drive_metadata_stream(
            stream,
            &Mutex::new(router),
            CLUSTER,
            &api_resource,
            &channels,
            &clock,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(
            outcome,
            DriftStreamOutcome::Ended,
            "a 500 is retried by kube's watcher, not parked by us"
        );
        assert_eq!(
            receivers[0]
                .try_recv()
                .expect("the post-error event still triggers")
                .namespace
                .as_deref(),
            Some("team-a")
        );
    }

    /// A re-list (`Init`/`InitApply`/`InitDone`) seeds baselines and triggers nothing: reconnecting a
    /// watch must not produce a reconcile storm.
    #[tokio::test]
    async fn a_relist_seeds_baselines_without_triggering() {
        let config = DriftWatcherConfig::from_flag(true);
        let (router, _echo) = router_with_app(&config, &[("team-a", "payments")], None);
        let (channels, mut receivers) = channels(8, vec![Some("team-a".to_owned())]);
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap"));
        let clock = TestClock::new();
        let stream = futures::stream::iter(vec![
            Ok(watcher::Event::Init),
            Ok(watcher::Event::InitApply(object(metadata(
                "settings",
                "payments",
                None,
                "7",
                Some(&hash_a()),
            )))),
            Ok(watcher::Event::InitApply(object(metadata(
                "other",
                "payments",
                None,
                "8",
                Some(&hash_a()),
            )))),
            Ok(watcher::Event::InitDone),
        ]);

        let outcome = drive_metadata_stream(
            stream,
            &Mutex::new(router),
            CLUSTER,
            &api_resource,
            &channels,
            &clock,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(outcome, DriftStreamOutcome::Ended);
        assert!(
            receivers[0].try_recv().is_err(),
            "a re-list is the observed state, not drift"
        );
    }

    // ------------------------------------------------------------------
    // Watch planning
    // ------------------------------------------------------------------

    /// One `status.inventory` entry.
    ///
    /// `version` is the **bare** API version (`v1`), which is what the pipeline records
    /// (`Gvk::version`) and what `GroupVersionKind::gvk(group, version, kind)` expects — `apps/v1`
    /// here would build a GVK Kubernetes never serves, and the only reason it would still pass is the
    /// fallback to `resolve_kind`, which is exactly the bug the fixture must not hide.
    fn entry(key: &str, version: &str) -> StatusInventoryEntry {
        debug_assert!(
            !version.contains('/'),
            "inventory versions are bare API versions, not `group/version`"
        );
        StatusInventoryEntry::new(key, version)
    }

    /// The watch set is derived strictly from `status.inventory`: deduplicated across
    /// `Application`s, split per cluster, filterable by kind, and capped per cluster.
    #[test]
    fn the_watch_plan_is_deduplicated_filtered_and_capped_per_cluster() {
        let apps: Vec<(&str, Vec<StatusInventoryEntry>)> = vec![
            (
                "in-cluster",
                vec![
                    entry("/ConfigMap/payments/settings", "v1"),
                    entry("apps/Deployment/payments/api", "v1"),
                ],
            ),
            (
                // A second Application in the same cluster: `apps/Deployment` must not be watched
                // twice.
                "in-cluster",
                vec![entry("apps/Deployment/payments/worker", "v1")],
            ),
            ("edge", vec![entry("/Secret/payments/creds", "v1")]),
        ];
        let inventories: Vec<(&str, &[StatusInventoryEntry])> = apps
            .iter()
            .map(|(cluster, entries)| (*cluster, entries.as_slice()))
            .collect();

        let plan = plan_watch_requests(
            inventories.clone(),
            &DriftKindFilter::All,
            MAX_DRIFT_WATCHES,
        );
        assert_eq!(
            plan.requests,
            vec![
                WatchRequest {
                    cluster: "edge".to_owned(),
                    group: String::new(),
                    kind: "Secret".to_owned(),
                    version: "v1".to_owned(),
                },
                WatchRequest {
                    cluster: "in-cluster".to_owned(),
                    group: String::new(),
                    kind: "ConfigMap".to_owned(),
                    version: "v1".to_owned(),
                },
                WatchRequest {
                    cluster: "in-cluster".to_owned(),
                    group: "apps".to_owned(),
                    kind: "Deployment".to_owned(),
                    version: "v1".to_owned(),
                },
            ],
            "sorted by (cluster, group, kind), one request per (cluster, GVK)"
        );
        assert!(plan.capped.is_empty());
        assert_eq!(plan.unparsed, 0);

        // **Version-agnostic identity (GKNN):** two `Application`s reporting different *versions* of
        // the same kind must share one watch — a version is a non-key hint, never part of identity.
        let split_versions: Vec<(&str, Vec<StatusInventoryEntry>)> = vec![
            (
                "in-cluster",
                vec![entry("apps/Deployment/payments/api", "v1")],
            ),
            (
                "in-cluster",
                vec![entry("apps/Deployment/payments/worker", "v1beta1")],
            ),
        ];
        let split_inventories: Vec<(&str, &[StatusInventoryEntry])> = split_versions
            .iter()
            .map(|(cluster, entries)| (*cluster, entries.as_slice()))
            .collect();
        let deduplicated =
            plan_watch_requests(split_inventories, &DriftKindFilter::All, MAX_DRIFT_WATCHES);
        assert_eq!(
            deduplicated.requests.len(),
            1,
            "the same group/kind in one cluster is one watch, whatever version each app reported"
        );
        assert_eq!(deduplicated.requests[0].kind, "Deployment");
        assert!(
            !deduplicated.requests[0].version.is_empty(),
            "a served-version hint is kept when any Application reported one"
        );

        // `--drift-watcher-kinds`: `Deployment` in any group, plus the exact core `ConfigMap`.
        let filter = DriftKindFilter::parse(Some("Deployment,/ConfigMap")).expect("valid list");
        let filtered = plan_watch_requests(inventories.clone(), &filter, MAX_DRIFT_WATCHES);
        assert_eq!(
            filtered
                .requests
                .iter()
                .map(|request| request.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["ConfigMap", "Deployment"]
        );

        // `group/Kind` is exact: `Secret` is filtered out, and `apps/ConfigMap` would not match.
        let exact = DriftKindFilter::parse(Some("apps/Deployment")).expect("valid list");
        let exact_plan = plan_watch_requests(inventories.clone(), &exact, MAX_DRIFT_WATCHES);
        assert_eq!(exact_plan.requests.len(), 1);
        assert_eq!(exact_plan.requests[0].kind, "Deployment");

        // Per-cluster cap: `in-cluster` asks for two watches and gets one; `edge` asks for one and
        // keeps it. The excess is reported, never silently dropped.
        let capped = plan_watch_requests(inventories, &DriftKindFilter::All, 1);
        assert_eq!(capped.requests.len(), 2, "one per cluster");
        assert_eq!(capped.capped.get("in-cluster"), Some(&1));
        assert_eq!(capped.capped.get("edge"), None);
    }

    /// **`T18.1` `names()` resync:** a plan that still names a cluster the registry no longer serves
    /// must not keep that watch alive, which is the case a **lagged** `ClusterLifecycleEvent`
    /// subscriber would otherwise miss (the `Application` pointing at the revoked cluster keeps the
    /// request in the plan forever).
    #[test]
    fn a_revoked_cluster_loses_its_watches_even_when_the_removal_event_was_missed() {
        let apps: Vec<(&str, Vec<StatusInventoryEntry>)> = vec![
            (
                "in-cluster",
                vec![entry("/ConfigMap/payments/settings", "v1")],
            ),
            ("edge", vec![entry("/Secret/payments/creds", "v1")]),
        ];
        let inventories: Vec<(&str, &[StatusInventoryEntry])> = apps
            .iter()
            .map(|(cluster, entries)| (*cluster, entries.as_slice()))
            .collect();
        let plan = plan_watch_requests(inventories, &DriftKindFilter::All, MAX_DRIFT_WATCHES);
        assert_eq!(plan.requests.len(), 2, "both clusters are in the plan");

        // The registry still knows `edge`.
        let with_edge: BTreeSet<String> = [IN_CLUSTER, "edge"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let keys = watch_keys(&plan, &with_edge);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&("edge".to_owned(), GroupKind::new("", "Secret"))));

        // `edge`'s registration was revoked while this subscriber was lagged: `names()` no longer
        // lists it, so the running watch is cancelled on the next refresh.
        let without_edge: BTreeSet<String> = [IN_CLUSTER].into_iter().map(str::to_owned).collect();
        let keys = watch_keys(&plan, &without_edge);
        assert_eq!(
            keys,
            [("in-cluster".to_owned(), GroupKind::new("", "ConfigMap"))]
                .into_iter()
                .collect(),
            "an addressable check against `names()` is the only thing that cancels a dead cluster"
        );
    }

    /// **Finding M:** a padded `spec.destination.cluster` is the same cluster everywhere else
    /// (`sync.rs::the_destination_cluster_is_normalized_consistently` pins that), so the plan must
    /// name it the one way `wanted` and the echo record can match. Planned under the raw spelling,
    /// `watch_keys` filters the request out (the registry's `names()` never carries padding) while
    /// `resolve_watch_targets` still resolves it — so the supervisor spawned a watch one refresh and
    /// cancelled it the next, re-listing its whole kind every 30 s, forever.
    #[tokio::test]
    async fn a_padded_destination_cluster_plans_the_spelling_the_watch_set_uses() {
        let entries = [entry("/ConfigMap/payments/settings", "v1")];
        let inventories: Vec<(&str, &[StatusInventoryEntry])> = vec![
            ("  in-cluster  ", entries.as_slice()),
            // The same cluster, spelled plainly: two Apps, one watch.
            ("in-cluster", entries.as_slice()),
        ];
        let plan = plan_watch_requests(inventories, &DriftKindFilter::All, MAX_DRIFT_WATCHES);
        assert_eq!(
            plan.requests,
            vec![WatchRequest {
                cluster: IN_CLUSTER.to_owned(),
                group: String::new(),
                kind: "ConfigMap".to_owned(),
                version: "v1".to_owned(),
            }],
            "a padded name must plan (and deduplicate) under the trimmed spelling"
        );

        // The registry only ever reports unpadded names, so this is the set `wanted` is built from.
        let addressable: BTreeSet<String> = [IN_CLUSTER].into_iter().map(str::to_owned).collect();
        let wanted = watch_keys(&plan, &addressable);
        assert_eq!(
            wanted,
            [(IN_CLUSTER.to_owned(), GroupKind::new("", "ConfigMap"))]
                .into_iter()
                .collect(),
            "the planned watch must be wanted, or the supervisor spawns and cancels it forever"
        );

        // The target `resolve_watch_targets` builds for this request is admitted, so it is spawned
        // once and then kept by the next refresh (a stable spawn/cancel cycle is impossible).
        assert!(admits(
            &wanted,
            &watch_target(IN_CLUSTER, "", "v1", "ConfigMap")
        ));
        // Defence in depth: a target under any other spelling is never spawned, whatever resolution
        // says, because the next refresh's `retain` would cancel it again.
        assert!(!admits(
            &wanted,
            &watch_target("  in-cluster  ", "", "v1", "ConfigMap")
        ));
    }

    /// A malformed `status.inventory` key is counted and skipped; it never stops the whole plan.
    #[test]
    fn a_malformed_inventory_key_is_skipped_not_fatal() {
        let entries = vec![
            entry("not-a-gknn", "v1"),
            entry("/ConfigMap/payments/settings", "v1"),
        ];
        let plan = plan_watch_requests(
            [("in-cluster", entries.as_slice())],
            &DriftKindFilter::All,
            8,
        );
        assert_eq!(plan.unparsed, 1);
        assert_eq!(plan.requests.len(), 1);
        assert_eq!(plan.requests[0].kind, "ConfigMap");
    }

    /// `--drift-watcher-kinds` parsing is literal: a typo is an error, not a silent "watch nothing".
    #[test]
    fn the_kind_allow_list_parses_literally() {
        assert_eq!(
            DriftKindFilter::parse(None).expect("default"),
            DriftKindFilter::All
        );
        assert_eq!(
            DriftKindFilter::parse(Some("   ")).expect("blank means default"),
            DriftKindFilter::All
        );
        assert!(matches!(
            DriftKindFilter::parse(Some("ConfigMap,,Secret")),
            Err(DriftConfigError::EmptyKindEntry)
        ));
        // `Kind` (any group), `group/Kind` (exact) and `/Kind` (the core group) are all valid; only
        // a blank kind or more than one `/` cannot match an inventory key.
        let core =
            DriftKindFilter::parse(Some("/ConfigMap")).expect("the core group is expressible");
        assert!(core.allows("", "ConfigMap"));
        assert!(!core.allows("apps", "ConfigMap"));
        assert!(matches!(
            DriftKindFilter::parse(Some("apps/")),
            Err(DriftConfigError::InvalidKindEntry { .. })
        ));
        assert!(matches!(
            DriftKindFilter::parse(Some("a/b/ConfigMap")),
            Err(DriftConfigError::InvalidKindEntry { .. })
        ));

        let filter =
            DriftKindFilter::parse(Some(" Deployment , apps/Deployment ")).expect("valid list");
        assert!(filter.allows("apps", "Deployment"));
        assert!(
            filter.allows("extensions", "Deployment"),
            "`Kind` is group-agnostic"
        );
        assert!(!filter.allows("apps", "StatefulSet"));
        assert!(matches!(filter, DriftKindFilter::Only(_)));
    }

    /// The default configuration is **disabled**: nothing about a `v1.0` deployment changes until an
    /// operator opts in, and every window matches the roadmap numbers.
    #[test]
    fn the_defaults_are_disabled_and_bounded() {
        let config = DriftWatcherConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.kinds, DriftKindFilter::All);
        assert_eq!(config.max_watches, MAX_DRIFT_WATCHES);
        assert_eq!(config.debounce, Duration::from_secs(2));
        assert_eq!(config.max_debounce, Duration::from_secs(5));
        assert_eq!(config.echo_ttl, Duration::from_secs(60));
        assert_eq!(config.echo_capacity, 10_000);
        assert_eq!(config.fallback_cooldown, Duration::from_secs(15 * 60));
        assert_eq!(config.trigger_capacity, 256);
        assert!(config.max_debounce >= config.debounce);
        assert!(!DriftWatcherConfig::from_flag(false).enabled);
        assert!(DriftWatcherConfig::from_flag(true).enabled);

        // A zero capacity is clamped, because `mpsc::channel(0)` panics and `max_watches == 0` would
        // silently watch nothing.
        let clamped = DriftWatcherConfig::from_flag(true)
            .with_trigger_capacity(0)
            .with_max_watches(0)
            .with_echo(Duration::from_secs(1), 0)
            .with_debounce(Duration::from_secs(5), Duration::from_secs(1));
        assert_eq!(clamped.trigger_capacity, 1);
        assert_eq!(clamped.max_watches, 1);
        assert_eq!(clamped.echo_capacity, 1);
        assert_eq!(clamped.max_debounce, Duration::from_secs(5));
    }

    /// The label selector is the `T18.1` managed-by pair, built from the shared constants (so it can
    /// never drift from what is stamped).
    #[test]
    fn the_label_selector_matches_the_stamped_label() {
        assert_eq!(label_selector(), "ferriscd.io/managed-by=ferriscd");
        assert_eq!(
            label_selector(),
            format!(
                "{}={}",
                annotations::LABEL_MANAGED_BY,
                annotations::MANAGED_BY_FERRISCD
            )
        );
    }

    /// **Trap guard:** an observation keeps metadata only. The type is the proof: there is no place
    /// on it for a body, a spec, a status or a `Secret.data` payload.
    #[test]
    fn an_observation_never_carries_a_body() {
        let mut secret = metadata("creds", "payments", None, "9", Some(&hash_a()));
        secret.annotations = Some(std::collections::BTreeMap::from([(
            "kubectl.kubernetes.io/last-applied-configuration".to_owned(),
            "{\"data\":{\"password\":\"hunter2\"}}".to_owned(),
        )]));
        let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "Secret"));
        let observed = observed(&api_resource, &secret, false);
        let rendered = format!("{observed:?}");
        assert!(
            !rendered.contains("hunter2"),
            "an observation must never carry (or Debug-print) a Secret payload: {rendered}"
        );
        // A `ConfigMap`'s `data` would live on the object, not on the observation: the struct has
        // exactly these fields, so nothing else can be retained.
        assert_eq!(observed.key.kind, "Secret");
        assert_eq!(observed.key.namespace.as_deref(), Some("payments"));
        assert_eq!(observed.resource_version.as_deref(), Some("9"));
        assert!(app_ref("payments", "settings").namespace.is_some());
    }

    /// The supervisor derives its plan from the `Application` stores and maintains the app-hash
    /// index; it never lists `Application`s itself.
    #[tokio::test]
    async fn the_supervisor_plans_from_the_application_stores() {
        use ferriscd_crd::status::InventoryEntry as StatusEntry;

        let clusters = offline_cluster_manager().await;
        let mut application = app("ferriscd-system", "payments");
        application.status = Some(ApplicationStatus {
            inventory: vec![StatusEntry::new("/ConfigMap/payments/settings", "v1")],
            ..ApplicationStatus::default()
        });

        // The store every `NamespacedController` owns, driven the way the reflector drives it: one
        // `Apply` plus the `InitDone` that completes the list.
        let mut writer = reflector::store::Writer::<Application>::default();
        writer.apply_watcher_event(&watcher::Event::Init);
        writer.apply_watcher_event(&watcher::Event::InitApply(application));
        writer.apply_watcher_event(&watcher::Event::InitDone);
        let reader = writer.as_reader();
        let (channels, _receivers) = channels(8, vec![Some("ferriscd-system".to_owned())]);
        let watcher = DriftWatcher::new(
            DriftWatcherConfig::from_flag(true),
            clusters,
            vec![reader],
            Arc::new(channels),
            Arc::new(SelfEchoCache::with_defaults()),
            None,
            None,
        );

        let plan = watcher.plan();
        assert_eq!(plan.requests.len(), 1);
        assert_eq!(plan.requests[0].cluster, "in-cluster");
        assert_eq!(plan.requests[0].kind, "ConfigMap");
        assert_eq!(
            read_recover(&watcher.index).lookup(&ferriscd_engine::inventory::app_hash(
                "ferriscd-system",
                "payments"
            )),
            &[app_ref("ferriscd-system", "payments")],
            "the index is rebuilt from the stores on every plan"
        );
    }

    // ------------------------------------------------------------------
    // Finding M2: the trigger counter tracks deliveries, not candidates
    // ------------------------------------------------------------------

    /// **Finding M2:** expiring a debounce entry *candidates* a reconcile; only a scope that accepts
    /// it counts as a trigger. Otherwise a saturated queue would report work the controller never
    /// received.
    #[test]
    fn only_an_enqueued_trigger_is_counted() {
        let config = DriftWatcherConfig::from_flag(true);
        let metrics = Metrics::new();
        let (sender, _receiver) = tokio::sync::mpsc::channel(4);
        let channels = DriftTriggerChannels::new(
            vec![(Some("team-a".to_owned()), sender)],
            Some(metrics.clone()),
        );
        let echo = Arc::new(config.echo_cache());
        let index = Arc::new(std::sync::RwLock::new(AppHashIndex::new()));
        let owned = [app("team-a", "payments")];
        write_recover(&index).rebuild(owned.iter());
        let mut router = DriftRouter::new(&config, None, echo, index, Some(metrics.clone()));

        let now = Instant::now();
        assert_eq!(
            router.handle(&configmap("settings", "payments", "1", &hash_a()), now),
            DriftDecision::Debounced { apps: 1 }
        );
        let due = router.take_due(now + config.debounce);
        assert_eq!(due, vec![app_ref("team-a", "payments")]);
        assert!(
            scrape(&metrics).contains("ferriscd_drift_watcher_triggers_total 0"),
            "arming a debounce entry is not a trigger: {}",
            scrape(&metrics)
        );

        for item in &due {
            assert_eq!(channels.try_send(item), TriggerDelivery::Enqueued);
        }
        assert!(
            scrape(&metrics).contains("ferriscd_drift_watcher_triggers_total 1"),
            "the delivery is what counts: {}",
            scrape(&metrics)
        );
    }

    // ------------------------------------------------------------------
    // Finding C2: the supervisor keeps unchanged watches, and the gauge is honest
    // ------------------------------------------------------------------

    /// A `kube::Client` that never dials out, for the supervisor's `WatchTarget` fixtures.
    fn offline_client() -> kube::Client {
        kube::Client::new(
            tower::service_fn(|_request| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "ferriscd-system",
        )
    }

    fn watch_target(cluster: &str, group: &str, version: &str, kind: &str) -> WatchTarget {
        WatchTarget {
            cluster: cluster.to_owned(),
            api_resource: ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind)),
            client: offline_client(),
        }
    }

    /// A running watch fixture, optionally already parked and/or streaming.
    fn running_watch(
        target: &WatchTarget,
        epoch: u64,
        parked: Option<(DriftFallbackReason, Instant)>,
        streaming: bool,
    ) -> RunningWatch {
        let mut state = FallbackState::default();
        if let Some((reason, now)) = parked {
            state.park(reason, now, FALLBACK_COOLDOWN);
        }
        RunningWatch {
            api_resource: target.api_resource.clone(),
            epoch,
            state: Arc::new(Mutex::new(state)),
            active: Arc::new(AtomicBool::new(streaming)),
            stop: CancellationToken::new(),
        }
    }

    /// **Finding C2 (the main regression):** a refresh that resolves the same target must leave the
    /// running watch completely alone.
    ///
    /// The previous supervisor cancelled and respawned every watch on every 30 s tick. That
    /// discarded each task's `FallbackState` (so a refused kind retried, logged and counted every
    /// 30 s) and re-listed every watched kind for nothing.
    #[tokio::test]
    async fn an_unchanged_watch_target_is_kept() {
        let target = watch_target("in-cluster", "", "v1", "ConfigMap");
        let now = Instant::now();
        let watch = running_watch(&target, 0, None, true);

        assert_eq!(
            watch_disposition(Some(&watch), None, &target, 0, now),
            WatchDisposition::Keep,
            "the same target at the same cluster epoch must not be rebuilt"
        );
        // A `Rebuilt` cluster gets a new client (bumped epoch): the stream must be replaced.
        assert_eq!(
            watch_disposition(Some(&watch), None, &target, 1, now),
            WatchDisposition::Spawn
        );
        // A served version that moved is a different resource: also a new watch.
        let moved = watch_target("in-cluster", "", "v1beta1", "ConfigMap");
        assert_eq!(
            watch_disposition(Some(&watch), None, &moved, 0, now),
            WatchDisposition::Spawn
        );
        // Nothing running yet: spawn.
        assert_eq!(
            watch_disposition(None, None, &target, 0, now),
            WatchDisposition::Spawn
        );
    }

    /// **Finding C2 (the other half):** a parked watch is not respawned until its cooldown expires,
    /// and the cooldown survives a target change — a new client is no evidence that RBAC changed.
    #[tokio::test]
    async fn a_parked_watch_is_not_respawned_until_its_cooldown_expires() {
        let target = watch_target("in-cluster", "", "v1", "ConfigMap");
        let start = Instant::now();
        let parked = running_watch(
            &target,
            0,
            Some((DriftFallbackReason::Forbidden, start)),
            false,
        );
        let state = parked.state.clone();

        // Inside the cooldown: nothing is spawned, even though the epoch moved (a rebuilt client).
        assert_eq!(
            watch_disposition(Some(&parked), None, &target, 1, start + secs(60)),
            WatchDisposition::Parked
        );
        // The supervisor also consults a parking state that outlives the task it belonged to.
        assert_eq!(
            watch_disposition(
                None,
                Some(&state),
                &target,
                1,
                start + FALLBACK_COOLDOWN - secs(1)
            ),
            WatchDisposition::Parked,
            "a parked key that left `running` keeps its cooldown"
        );
        // Exactly at the boundary the cooldown has expired and the watch is retried.
        assert_eq!(
            watch_disposition(None, Some(&state), &target, 1, start + FALLBACK_COOLDOWN),
            WatchDisposition::Spawn
        );
    }

    /// **Finding C2 (the gauge):** `ferriscd_drift_watcher_active_watches` counts streams that are
    /// actually running, never a parked or restart-delayed task.
    #[tokio::test]
    async fn the_active_watch_gauge_counts_only_streaming_watches() {
        let configmap = watch_target("in-cluster", "", "v1", "ConfigMap");
        let secret = watch_target("in-cluster", "", "v1", "Secret");
        let deployment = watch_target("edge", "apps", "v1", "Deployment");
        let start = Instant::now();
        let mut running: BTreeMap<(String, GroupKind), RunningWatch> = BTreeMap::new();
        running.insert(
            ("in-cluster".to_owned(), configmap.group_kind()),
            running_watch(&configmap, 0, None, true),
        );
        running.insert(
            ("in-cluster".to_owned(), secret.group_kind()),
            running_watch(
                &secret,
                0,
                Some((DriftFallbackReason::Forbidden, start)),
                false,
            ),
        );
        running.insert(
            ("edge".to_owned(), deployment.group_kind()),
            running_watch(&deployment, 0, None, true),
        );
        assert_eq!(
            active_watches(&running),
            2,
            "the parked (or restart-delayed) task must not be reported as an active watch"
        );
    }

    /// **Finding C2 (logging):** the cap and GKNN warnings are emitted once per *change*, not once
    /// per 30 s refresh, and the recovery is announced too.
    #[test]
    fn plan_diagnostics_are_logged_once_per_change() {
        let mut logged = PlanDiagnostics::default();
        let mut plan = WatchPlan {
            unparsed: 2,
            ..WatchPlan::default()
        };
        plan.capped.insert("in-cluster".to_owned(), 3);
        logged.report(&plan, 64);
        assert_eq!(
            logged,
            PlanDiagnostics {
                capped: plan.capped.clone(),
                unparsed: 2,
            }
        );
        // A second identical refresh is a no-op: nothing to re-log.
        let unchanged = logged.clone();
        logged.report(&plan, 64);
        assert_eq!(logged, unchanged);
        // A change is logged, and so is the recovery.
        let smaller = WatchPlan {
            unparsed: 2,
            ..WatchPlan::default()
        };
        logged.report(&smaller, 64);
        assert!(logged.capped.is_empty());
        let clean = WatchPlan::default();
        logged.report(&clean, 64);
        assert_eq!(logged, PlanDiagnostics::default());
    }

    // ------------------------------------------------------------------
    // Wire level: what a drift watch actually asks the API server for
    // ------------------------------------------------------------------

    /// One request captured by the mock API server.
    #[derive(Clone, Debug)]
    struct Captured {
        path: String,
        query: String,
        accept: Option<String>,
    }

    /// `form_urlencoded` percent-encodes the selector's `/` and `=`; decoding those two is enough to
    /// assert the exact `labelSelector` pair.
    fn decoded(query: &str) -> String {
        query.replace("%2F", "/").replace("%3D", "=")
    }

    /// A metadata-only list response: `metadata` and nothing else.
    fn metadata_list_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "apiVersion": "meta.k8s.io/v1",
            "kind": "PartialObjectMetadataList",
            "metadata": { "resourceVersion": "7" },
            "items": [{
                "metadata": {
                    "name": "settings",
                    "namespace": "payments",
                    "uid": "uid-settings",
                    "resourceVersion": "7",
                    "labels": { annotations::LABEL_MANAGED_BY: annotations::MANAGED_BY_FERRISCD },
                }
            }]
        }))
        .expect("the fixture serializes")
    }

    /// **Finding H2 (wire level):** the *production* watch builder asks for metadata only and for
    /// the `ferriscd.io/managed-by=ferriscd` selector, on **both** the list and the watch request.
    ///
    /// This is asserted against the real requests a mock API server receives, not against the shape
    /// of an event: the two `Accept` values are what guarantee no `.spec`/`.status`/`Secret.data`
    /// byte is ever returned, and the query is what keeps foreign objects off the wire.
    #[tokio::test]
    async fn the_metadata_watch_asks_for_metadata_only_and_is_label_scoped() {
        // The type-level half: `PartialObjectMeta` *is* the metadata-only request.
        assert!(
            PartialObjectMeta::<DynamicObject>::metadata_api(),
            "`PartialObjectMeta` must be the metadata API type"
        );
        assert!(
            !DynamicObject::metadata_api(),
            "a whole-object `DynamicObject` would return spec/status/data"
        );

        let seen: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let client = kube::Client::new(
            tower::service_fn(move |request: http::Request<kube::client::Body>| {
                let recorder = recorder.clone();
                async move {
                    let path = request.uri().path().to_owned();
                    let query = request.uri().query().unwrap_or_default().to_owned();
                    let accept = request
                        .headers()
                        .get(http::header::ACCEPT)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    let watching = query.split('&').any(|pair| pair == "watch=true");
                    lock_recover(&recorder).push(Captured {
                        path,
                        query,
                        accept,
                    });
                    if watching {
                        // A real watch stays open, and so must this one: answering it with an
                        // empty body makes `kube`'s watcher retry *within one poll*, which would
                        // bury the assertion below in thousands of requests.
                        return futures::future::pending().await;
                    }
                    let response = http::Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_TYPE, "application/json")
                        .body(kube::client::Body::from(metadata_list_body()))
                        .expect("the scripted response builds");
                    Ok::<_, std::convert::Infallible>(response)
                }
            }),
            "ferriscd-system",
        );
        let target = WatchTarget {
            cluster: "in-cluster".to_owned(),
            api_resource: ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "ConfigMap")),
            client,
        };

        // Drive the production builder: list (`Init` … `InitDone`), then the watch request.
        let mut stream = Box::pin(metadata_watch_stream(&target));
        let mut listed = false;
        while let Some(event) = tokio::time::timeout(Duration::from_secs(10), stream.next())
            .await
            .expect("the watcher must deliver the list")
        {
            match event {
                Ok(watcher::Event::InitDone) => {
                    listed = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("the scripted list must not fail: {error}"),
            }
        }
        assert!(listed, "the metadata watch must list first (`InitDone`)");
        // Drive the stream until the mock has *seen* the watch request. The mock deliberately never
        // answers it (a real watch stays open), so the two futures are raced and the spin's
        // `yield_now` only reschedules — no clock, no sleep, and no dependence on how many polls
        // kube's watcher needs.
        let watch_requested = tokio::select! {
            () = async {
                for _ in 0..1_000 {
                    if lock_recover(&seen).len() >= 2 {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            } => true,
            _ = stream.next() => false,
        };
        assert!(
            watch_requested,
            "the watcher must issue a watch request after its list, got: {:?}",
            lock_recover(&seen)
        );
        drop(stream);

        let requests = lock_recover(&seen).clone();
        assert_eq!(
            requests.len(),
            2,
            "one list and one watch request were expected, got: {requests:?}"
        );
        let list = &requests[0];
        let watch = &requests[1];
        assert_eq!(
            list.path, "/api/v1/configmaps",
            "cluster-wide, by `Api::all_with`"
        );
        assert_eq!(watch.path, "/api/v1/configmaps");
        assert!(
            !list.query.split('&').any(|pair| pair == "watch=true"),
            "the first request is the list: {list:?}"
        );
        assert!(
            watch.query.split('&').any(|pair| pair == "watch=true"),
            "the second request is the watch: {watch:?}"
        );
        // **Metadata only**, on both requests (`PartialObjectMetadataList` on the list).
        for request in [list, watch] {
            let accept = request
                .accept
                .as_deref()
                .unwrap_or_else(|| panic!("no `Accept` header on {request:?}"));
            assert!(
                accept.starts_with("application/json;as=PartialObjectMetadata"),
                "a drift watch must ask for PartialObjectMetadata, got {accept:?}"
            );
        }
        assert_eq!(
            list.accept.as_deref(),
            Some("application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1")
        );
        assert_eq!(
            watch.accept.as_deref(),
            Some("application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1")
        );
        // **Label scoped**, server-side, on both requests.
        for request in [list, watch] {
            assert!(
                decoded(&request.query)
                    .split('&')
                    .any(|pair| pair == "labelSelector=ferriscd.io/managed-by=ferriscd"),
                "both requests must carry the managed-by selector, got {:?}",
                request.query
            );
        }
    }

    /// A `ClusterManager` over a service that never dials out: enough to build the supervisor, whose
    /// requests are only issued when a stream is polled.
    async fn offline_cluster_manager() -> Arc<ClusterManager> {
        use crate::cluster_manager::{
            ClusterHandle, ClusterName, ClusterOptions, KubeClusterBuilder,
        };
        use crate::impersonation::ImpersonationPool;

        let client = kube::Client::new(
            tower::service_fn(|_request| async {
                Ok::<_, std::convert::Infallible>(http::Response::new(kube::client::Body::empty()))
            }),
            "ferriscd-system",
        );
        let config = kube::Config::new("http://127.0.0.1:1".parse().expect("valid url"));
        let pool = ImpersonationPool::new(&config).expect("the pool builds offline");
        let in_cluster = Arc::new(ClusterHandle::new(
            ClusterName::in_cluster(),
            client.clone(),
            crate::discovery::DiscoveryCache::new(client),
            Arc::new(pool),
        ));
        let options = ClusterOptions::strict();
        Arc::new(ClusterManager::new(
            in_cluster,
            "ferriscd-system",
            options,
            Arc::new(KubeClusterBuilder::new(options)),
        ))
    }
}
