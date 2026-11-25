//! Union live-state fetcher: the *live* half of the `v0.2` reconcile pass.
//!
//! A `desired`-only fetch is trap T1: a resource deleted from Git is invisible, so it can
//! never be pruned and leaks forever. [`ClusterStateReader::fetch_live`] therefore fetches
//! `to_fetch = desired_gknn ∪ prev_inventory_gknn` (see
//! [`ferriscd_engine::inventory::to_fetch`]) and classifies every key into a
//! [`LiveState`]:
//!
//! | State | Meaning | Sync consequence |
//! |---|---|---|
//! | [`LiveState::Present`] | the object exists, ownership classified against the expected `tracking-id` | diff/apply |
//! | [`LiveState::Missing`] | `404`/`410`; the namespace exists (or is not ours to create) | create (apply) |
//! | [`LiveState::DeferredPendingCrd`] | kind not served yet, but a `CustomResourceDefinition` in `desired` defines it | requeue, never fail |
//! | [`LiveState::DeferredPendingNamespace`] | `404` and the object's namespace is absent and a `Namespace` manifest in `desired` declares it | requeue, never fail |
//! | [`LiveState::OrphanGvkGone`] | an orphan whose kind is no longer served (its CRD was deleted) | treat as already pruned |
//!
//! Two properties are load-bearing:
//!
//! * **Bounded concurrency.** Up to [`LIVE_FETCH_CONCURRENCY`] (16) GETs are in flight per
//!   pass via `futures::stream::iter(..).buffer_unordered(16)`. A 500-object bundle must not
//!   open 500 sockets, and no blocking I/O runs on a Tokio worker (every fetch is a plain
//!   async `kube` request; `spawn_blocking` is only used by the manifest and repo layers).
//!   The per-namespace existence verdict is memoized for the pass, so N keys that `404` in
//!   the same namespace cost one `Namespace` probe instead of N.
//! * **Nothing is swallowed.** A `404`/`410` is a *classification*, but any other API error
//!   (5xx, 403, transport) and any discovery outage is surfaced as a typed
//!   [`LiveStateError`] so the reconcile fails and retries instead of silently believing the
//!   object is gone.
//!
//! This module never *creates* a namespace: `syncOptions.createNamespace` is rejected by the
//! pipeline, so a namespace is "ours to wait for" only when a `Namespace` manifest in the
//! same bundle declares it (on-demand creation is `T08.3`).
//!
//! The identity of every key is the version-agnostic GKNN
//! [`ResourceKey`], so a resolution that only finds a *different* served version of the same
//! group + kind still fetches the right object (finding C2).

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ferriscd_crd::Application;
use ferriscd_engine::inventory::{
    Inventory, Ownership, classify_ownership, to_fetch, tracking_id_for,
};
use ferriscd_engine::manifest::ResourceKey;
use futures::TryStreamExt;
use futures::stream::{self, StreamExt};
use kube::ResourceExt;
use kube::api::{Api, ApiResource, DynamicObject};
use kube::core::gvk::GroupVersionKind;
use kube::discovery::{ApiCapabilities, Scope};

use crate::discovery::{DiscoveryCache, DiscoveryError};
use crate::scope::InBundleCrd;

/// Maximum number of live GETs in flight during one [`ClusterStateReader::fetch_live`] pass.
///
/// Sixteen is the documented bound (T06.3): large enough that a 500-resource bundle costs a
/// few round trips instead of 500, small enough that a reconcile can never flood the API
/// server or exhaust the client's connection pool.
pub const LIVE_FETCH_CONCURRENCY: usize = 16;

/// Result of one live fetch or namespace probe.
pub type LiveFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, LiveStateError>> + Send + 'a>>;

/// One object to fetch: its version-agnostic identity, version *hints* and provenance.
///
/// The key never carries a version (ADR-003); [`FetchRequest::versions`] only *hints* which
/// served `group/version` to resolve first. When no hint resolves, the reader falls back to
/// whatever version of that group + kind the cluster serves, because the object's identity
/// does not depend on the version it is read through.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRequest {
    /// Version-agnostic identity (GKNN).
    pub key: ResourceKey,
    /// Candidate API versions, most preferred first (desired GVK version, then the
    /// `status.inventory` version hint). May be empty.
    pub versions: Vec<String>,
    /// `true` when the key is a **previous** inventory entry that is no longer desired.
    ///
    /// An orphan whose kind has disappeared entirely is [`LiveState::OrphanGvkGone`] rather
    /// than an error: the CRD was deleted, so the object went with it.
    pub orphan: bool,
}

impl FetchRequest {
    /// Builds a request for `key` with the given version hints.
    #[must_use]
    pub fn new(key: ResourceKey, versions: Vec<String>) -> Self {
        Self {
            key,
            versions,
            orphan: false,
        }
    }

    /// Marks the request as a previous-inventory-only (orphan) resource.
    #[must_use]
    pub fn as_orphan(mut self) -> Self {
        self.orphan = true;
        self
    }

    /// Records an additional version hint if it is non-empty and not already known.
    fn push_version(&mut self, version: &str) {
        let version = version.trim();
        if version.is_empty() || self.versions.iter().any(|known| known == version) {
            return;
        }
        self.versions.push(version.to_owned());
    }
}

/// Builds the union fetch list (`desired ∪ prev_inventory`) with version hints and orphan
/// flags, sorted by [`ResourceKey`].
///
/// This is the bridge between the pure inventory algebra
/// ([`ferriscd_engine::inventory::to_fetch`]) and the fetcher: desired versions are preferred
/// over `status.inventory` hints, so an API upgrade reads the object through the version the
/// manifest asks for and only falls back to the recorded hint.
#[must_use]
pub fn plan_fetch(desired: &Inventory, prev_inventory: &Inventory) -> Vec<FetchRequest> {
    to_fetch(desired, prev_inventory)
        .into_iter()
        .map(|key| {
            let mut request = FetchRequest::new(key.clone(), Vec::new());
            if let Some(entry) = desired.get(&key) {
                request.push_version(&entry.version);
            }
            if let Some(entry) = prev_inventory.get(&key) {
                request.push_version(&entry.version);
            }
            if desired.contains_key(&key) {
                request
            } else {
                request.as_orphan()
            }
        })
        .collect()
}

/// Classification of one fetched key.
#[derive(Clone, Debug, PartialEq)]
pub enum LiveState {
    /// The live object and its ownership verdict against the expected `tracking-id`.
    ///
    /// Boxed because a decoded object dwarfs every other variant; the enum is moved around per
    /// key on each reconcile.
    Present(Box<DynamicObject>, Ownership),

    /// The API server reports the object as absent (`404` or `410`).
    ///
    /// A `404` for an orphan counts as a confirmed prune; a `404` for a desired resource
    /// means "create it".
    Missing,

    /// The kind is not served yet, but a `CustomResourceDefinition` in `desired` defines it.
    DeferredPendingCrd,

    /// The object's namespace does not exist yet and a `Namespace` manifest in the same bundle
    /// declares it (this sync never creates a namespace on demand).
    DeferredPendingNamespace,

    /// An orphan whose kind is no longer served: its CRD was deleted, so the object is gone.
    OrphanGvkGone,
}

impl LiveState {
    /// Returns `true` for [`LiveState::Present`].
    #[must_use]
    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present(..))
    }

    /// Returns `true` for the two "cannot touch this yet" states.
    ///
    /// A deferred resource is **not** an error: the sync requeues and retries once the CRD is
    /// established or the namespace exists (finding C3 prepares the deferred dry-run skip).
    #[must_use]
    pub fn is_deferred(&self) -> bool {
        matches!(
            self,
            Self::DeferredPendingCrd | Self::DeferredPendingNamespace
        )
    }

    /// Returns `true` when the object is known not to exist.
    #[must_use]
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Missing | Self::OrphanGvkGone)
    }

    /// Returns the ownership verdict of a present object.
    #[must_use]
    pub fn ownership(&self) -> Option<&Ownership> {
        match self {
            Self::Present(_, ownership) => Some(ownership),
            _ => None,
        }
    }

    /// Returns the live object, if present.
    #[must_use]
    pub fn object(&self) -> Option<&DynamicObject> {
        match self {
            Self::Present(object, _) => Some(object.as_ref()),
            _ => None,
        }
    }
}

/// Deterministic, key-ordered result of [`ClusterStateReader::fetch_live`].
pub type LiveStateMap = BTreeMap<ResourceKey, LiveState>;

/// Identity of the owning `Application`, used to compute the expected `tracking-id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackingOwner {
    /// Namespace of the `Application`.
    pub namespace: String,
    /// Name of the `Application`.
    pub name: String,
}

impl TrackingOwner {
    /// Builds an owner identity.
    #[must_use]
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    /// Builds the owner identity of `app`.
    ///
    /// Returns `None` when the application has no namespace: a `tracking-id` without an
    /// application namespace can never be parsed back, so ownership checks would silently
    /// misclassify every live object.
    #[must_use]
    pub fn for_application(app: &Application) -> Option<Self> {
        let namespace = app.namespace().unwrap_or_default();
        if namespace.trim().is_empty() {
            return None;
        }
        Some(Self::new(namespace, app.name_any()))
    }

    /// Renders the expected `tracking-id` for `key`.
    #[must_use]
    pub fn expected_tracking_id(&self, key: &ResourceKey) -> String {
        tracking_id_for(&self.namespace, &self.name, key)
    }
}

/// One GET to perform, already resolved to a concrete `ApiResource`.
#[derive(Clone, Copy, Debug)]
pub struct FetchTarget<'a> {
    /// Discovered resource (carries the real plural name).
    pub api_resource: &'a ApiResource,
    /// Namespace for a namespaced resource; `None` fetches cluster-wide.
    pub namespace: Option<&'a str>,
    /// Object name.
    pub name: &'a str,
}

/// Kubernetes read access used by [`ClusterStateReader`].
///
/// Production is [`DynamicApiSource`] (a dynamic `Api` per GVK). Tests inject a scripted fake
/// so every classification — including `404`, `410`, a namespace that exists or not, and hard
/// API failures — is provable without a cluster.
pub trait LiveObjectSource: Send + Sync + 'static {
    /// Fetches one object; `Ok(None)` means the API server reports it absent (`404`/`410`).
    ///
    /// # Errors
    ///
    /// Any other API failure must be returned as an error: treating a `500`/`403` as
    /// "missing" would let the controller recreate objects that already exist.
    fn get<'a>(&'a self, target: FetchTarget<'a>) -> LiveFuture<'a, Option<DynamicObject>>;

    /// Returns whether `namespace` exists.
    fn namespace_exists<'a>(&'a self, namespace: &'a str) -> LiveFuture<'a, bool>;
}

/// [`LiveObjectSource`] backed by the Kubernetes API server through dynamic `Api` clients.
#[derive(Clone)]
pub struct DynamicApiSource {
    client: kube::Client,
}

impl std::fmt::Debug for DynamicApiSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicApiSource").finish_non_exhaustive()
    }
}

impl DynamicApiSource {
    /// Builds a source over `client`.
    #[must_use]
    pub fn new(client: kube::Client) -> Self {
        Self { client }
    }
}

impl LiveObjectSource for DynamicApiSource {
    fn get<'a>(&'a self, target: FetchTarget<'a>) -> LiveFuture<'a, Option<DynamicObject>> {
        let client = self.client.clone();
        Box::pin(async move {
            let api = match target.namespace {
                Some(namespace) => {
                    Api::<DynamicObject>::namespaced_with(client, namespace, target.api_resource)
                }
                None => Api::<DynamicObject>::all_with(client, target.api_resource),
            };

            match api.get(target.name).await {
                Ok(object) => Ok(Some(object)),
                Err(err) if is_absent(&err) => Ok(None),
                Err(err) => Err(LiveStateError::api(
                    format!(
                        "{}/{}/{}",
                        target.api_resource.api_version, target.api_resource.kind, target.name
                    ),
                    &err,
                )),
            }
        })
    }

    fn namespace_exists<'a>(&'a self, namespace: &'a str) -> LiveFuture<'a, bool> {
        let client = self.client.clone();
        Box::pin(async move {
            let api_resource = ApiResource::from_gvk(&GroupVersionKind::gvk("", "v1", "Namespace"));
            let api = Api::<DynamicObject>::all_with(client, &api_resource);
            match api.get(namespace).await {
                Ok(_) => Ok(true),
                Err(err) if is_absent(&err) => Ok(false),
                Err(err) => Err(LiveStateError::api(
                    format!("/Namespace//{namespace}"),
                    &err,
                )),
            }
        })
    }
}

/// Returns whether `err` means "the object is not there" (`404 NotFound` or `410 Gone`).
///
/// `410` is treated exactly like `404` (a CRD-driven kind can report `Gone` after deletion),
/// so a genuine absence never fails a reconcile.
fn is_absent(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(status) if status.code == 404 || status.code == 410)
}

/// Errors raised while classifying live state.
#[derive(Debug, thiserror::Error)]
pub enum LiveStateError {
    /// A Kubernetes API call failed with something other than `404`/`410`.
    #[error("kubernetes API error {code} while fetching {resource}: {message}")]
    Api {
        /// Canonical identity of the object being fetched.
        resource: String,
        /// HTTP status code (`0` for transport/decode failures).
        code: u16,
        /// Server-provided message.
        ///
        /// Not *guaranteed* payload-free: a `400`/`422` from the API server can quote the value
        /// it rejected. The dry-run path replaces such a message with
        /// [`crate::dry_run::REDACTED_SERVER_MESSAGE`] for `v1/Secret` because a diff is reported
        /// to users; a `GET` failure here is a reconcile error, but the same caution applies
        /// before logging one.
        message: String,
    },

    /// The API server does not serve the group + kind in any version, and no in-bundle
    /// `CustomResourceDefinition` defines it.
    #[error(
        "no served API version for {gvk}: the cluster does not serve the kind and no \
         CustomResourceDefinition in the desired set defines it"
    )]
    UnknownKind {
        /// `group/kind` (version-agnostic identity the key is keyed on).
        gvk: String,
    },

    /// A key's scope contradicts the discovered scope of its kind.
    #[error("live state of {resource} cannot be fetched: {message}")]
    ScopeMismatch {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// What is inconsistent.
        message: String,
    },

    /// API discovery failed (refresh outage) while resolving a GVK.
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
}

impl LiveStateError {
    /// Builds an [`LiveStateError::Api`] from a `kube` error.
    fn api(resource: impl Into<String>, err: &kube::Error) -> Self {
        let code = match err {
            kube::Error::Api(status) => status.code,
            _ => 0,
        };
        Self::Api {
            resource: resource.into(),
            code,
            message: err.to_string(),
        }
    }

    /// Returns whether retrying the same reconcile can plausibly succeed.
    ///
    /// Deterministic input problems (a kind nobody serves, an inconsistent key) are terminal;
    /// transport failures and `5xx`/`429`/`409` are transient, mirroring
    /// [`crate::ReconcileError::failure_class`].
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Api { code, .. } => matches!(*code, 0 | 408 | 409 | 425 | 429) || *code >= 500,
            Self::UnknownKind { .. } | Self::ScopeMismatch { .. } => false,
            Self::Discovery(err) => !err.is_no_matches_for_kind(),
        }
    }
}

/// Union live-state fetcher (`desired ∪ prev_inventory`).
#[derive(Clone)]
pub struct ClusterStateReader {
    source: Arc<dyn LiveObjectSource>,
}

impl std::fmt::Debug for ClusterStateReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClusterStateReader")
            .field("concurrency", &LIVE_FETCH_CONCURRENCY)
            .finish_non_exhaustive()
    }
}

impl ClusterStateReader {
    /// Builds a reader over `source`.
    #[must_use]
    pub fn new(source: Arc<dyn LiveObjectSource>) -> Self {
        Self { source }
    }

    /// The live-state source this reader reads through.
    ///
    /// Used to rebuild a reader for the same cluster with a different identity (`T12.3`): the
    /// source is the only state a reader holds.
    #[must_use]
    pub fn source(&self) -> &Arc<dyn LiveObjectSource> {
        &self.source
    }

    /// Reads the live state of every requested key with bounded concurrency.
    ///
    /// Requests are de-duplicated by [`ResourceKey`] (first hint set wins) and executed with
    /// at most [`LIVE_FETCH_CONCURRENCY`] GETs in flight. The returned map is ordered by
    /// [`ResourceKey`], so two passes over the same cluster produce byte-identical results and
    /// `/status` never churns.
    ///
    /// Namespace existence is probed at most once per distinct namespace for the whole pass
    /// (see [`NamespaceVerdicts`]).
    ///
    /// # Errors
    ///
    /// Returns the first [`LiveStateError`] encountered (fail fast): a reconcile that cannot
    /// read live state must retry, not guess. `404`/`410` never produce an error — they are
    /// classifications ([`LiveState::Missing`]).
    pub async fn fetch_live(
        &self,
        to_fetch: &[FetchRequest],
        discovery: &DiscoveryCache,
        in_bundle_crds: &[InBundleCrd],
        in_bundle_namespaces: &[String],
        owner: &TrackingOwner,
    ) -> Result<LiveStateMap, LiveStateError> {
        let namespaces = NamespaceVerdicts::default();
        let fetched: Vec<(ResourceKey, LiveState)> = stream::iter(dedupe(to_fetch))
            .map(|request| async {
                let state = self
                    .fetch_one(
                        &request,
                        discovery,
                        in_bundle_crds,
                        in_bundle_namespaces,
                        &namespaces,
                        owner,
                    )
                    .await?;
                Ok::<(ResourceKey, LiveState), LiveStateError>((request.key, state))
            })
            .buffer_unordered(LIVE_FETCH_CONCURRENCY)
            .try_collect()
            .await?;

        // Bounded concurrency makes completion order arbitrary; sort so the result is
        // deterministic regardless of which GET finished first.
        let mut fetched = fetched;
        fetched.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(fetched.into_iter().collect())
    }

    /// Returns whether `namespace` exists in the cluster.
    ///
    /// Used by `syncOptions.createNamespace` (T08.3) to decide whether the destination namespace
    /// still has to be created: re-applying it every pass would be idempotent but would still
    /// bump its `metadata.resourceVersion` (and therefore churn `managedFields`) on every
    /// reconcile of an otherwise settled `Application`.
    ///
    /// # Errors
    ///
    /// Propagates the source's transport/authorization failures; an absent namespace is
    /// `Ok(false)`, never an error.
    pub async fn namespace_exists(&self, namespace: &str) -> Result<bool, LiveStateError> {
        self.source.namespace_exists(namespace).await
    }

    /// Reads one object verbatim, with no ownership classification.
    ///
    /// Used by the `Established` wait (T08.3): a `CustomResourceDefinition` is read for its
    /// `status.conditions` only, and classifying its `tracking-id` would be noise. `404`/`410`
    /// (whether surfaced as `Ok(None)` or as an error) is `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Propagates every other transport/authorization failure: a pass that cannot read the CRD
    /// must retry instead of assuming it is not established.
    pub async fn get_object(
        &self,
        api_resource: &ApiResource,
        namespace: Option<&str>,
        name: &str,
    ) -> Result<Option<DynamicObject>, LiveStateError> {
        let target = FetchTarget {
            api_resource,
            namespace,
            name,
        };
        match self.source.get(target).await {
            Ok(object) => Ok(object),
            Err(LiveStateError::Api {
                code: 404 | 410, ..
            }) => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Re-reads and re-classifies **one** key, without any per-pass memoization.
    ///
    /// Used immediately before a mutation (the pruner re-checks ownership right before
    /// `Delete`): the pass-level [`Self::fetch_live`] result can be stale by the time the
    /// delete is issued, and a foreign takeover must never be pruned (trap T10, TOCTOU).
    ///
    /// The request is treated as an orphan, so an absent kind is [`LiveState::OrphanGvkGone`]
    /// rather than an error.
    ///
    /// # Errors
    ///
    /// Mirrors [`Self::fetch_live`]: only non-`404`/`410` API failures and discovery outages
    /// are errors.
    pub async fn recheck(
        &self,
        key: &ResourceKey,
        version_hint: Option<&str>,
        discovery: &DiscoveryCache,
        in_bundle_crds: &[InBundleCrd],
        in_bundle_namespaces: &[String],
        owner: &TrackingOwner,
    ) -> Result<LiveState, LiveStateError> {
        let mut request = FetchRequest::new(key.clone(), Vec::new()).as_orphan();
        if let Some(version) = version_hint {
            request.push_version(version);
        }
        let namespaces = NamespaceVerdicts::default();
        self.fetch_one(
            &request,
            discovery,
            in_bundle_crds,
            in_bundle_namespaces,
            &namespaces,
            owner,
        )
        .await
    }

    /// Classifies one key (see the module table).
    async fn fetch_one(
        &self,
        request: &FetchRequest,
        discovery: &DiscoveryCache,
        in_bundle_crds: &[InBundleCrd],
        in_bundle_namespaces: &[String],
        namespaces: &NamespaceVerdicts,
        owner: &TrackingOwner,
    ) -> Result<LiveState, LiveStateError> {
        let key = &request.key;
        let Some((api_resource, capabilities)) =
            resolve_api(discovery, key, &request.versions).await?
        else {
            // Nothing the cluster serves matches this group + kind.
            if request.orphan {
                // The CRD is gone, so the object went with it: nothing left to prune.
                return Ok(LiveState::OrphanGvkGone);
            }
            if in_bundle_crds
                .iter()
                .any(|crd| crd.group == key.group && crd.kind == key.kind)
            {
                // CRD + CR in one bundle: the CR is applied on a later pass, never failed.
                return Ok(LiveState::DeferredPendingCrd);
            }
            return Err(LiveStateError::UnknownKind {
                gvk: format!("{}/{}", key.group, key.kind),
            });
        };

        let namespace = match capabilities.scope {
            Scope::Namespaced => match key.namespace.as_deref() {
                Some(namespace) if !namespace.trim().is_empty() => Some(namespace),
                _ => {
                    return Err(LiveStateError::ScopeMismatch {
                        resource: key.canonical(),
                        message: "discovery reports a namespaced kind but the inventory key \
                                  carries no namespace"
                            .to_owned(),
                    });
                }
            },
            // Discovery wins over the key: a kind that became cluster-scoped is fetched
            // cluster-wide even if an old inventory entry still records a namespace.
            Scope::Cluster => None,
        };

        let expected = owner.expected_tracking_id(key);
        let target = FetchTarget {
            api_resource: &api_resource,
            namespace,
            name: &key.name,
        };

        // Defense in depth: a source that surfaces `404`/`410` directly (instead of
        // `Ok(None)`) must still be classified as absent, never as a hard failure.
        let fetched = match self.source.get(target).await {
            Ok(object) => object,
            Err(LiveStateError::Api {
                code: 404 | 410, ..
            }) => None,
            Err(err) => return Err(err),
        };

        let Some(object) = fetched else {
            if let Some(namespace) = namespace
                && namespace_is_ours(namespace, in_bundle_namespaces)
                && !namespaces.exists(self.source.as_ref(), namespace).await?
            {
                // The namespace does not exist yet and this sync creates it: requeue, do not
                // fail. The live existence check is what keeps "the object was deleted while
                // its namespace exists" classified as `Missing` (so self-heal re-creates it)
                // instead of looping on a pending namespace forever.
                return Ok(LiveState::DeferredPendingNamespace);
            }
            return Ok(LiveState::Missing);
        };

        let ownership = classify_ownership(&object, &expected);
        Ok(LiveState::Present(Box::new(object), ownership))
    }
}

/// Per-pass memo of `namespace_exists` verdicts.
///
/// A single reconcile can `404` on many keys that share one namespace (a whole bundle in a
/// fresh destination namespace, for example). Probing once per key would multiply API calls
/// for no new information, so the verdict is cached for exactly one
/// [`ClusterStateReader::fetch_live`] pass and dropped afterwards: a namespace created by this
/// very sync is re-probed on the next reconcile.
#[derive(Default)]
struct NamespaceVerdicts {
    verdicts: tokio::sync::Mutex<BTreeMap<String, bool>>,
}

impl NamespaceVerdicts {
    /// Returns whether `namespace` exists, probing the API at most once per pass.
    async fn exists(
        &self,
        source: &dyn LiveObjectSource,
        namespace: &str,
    ) -> Result<bool, LiveStateError> {
        // The lock is deliberately held across the probe: concurrent 404s for the *same*
        // namespace then collapse into one GET instead of a thundering herd of duplicates.
        let mut verdicts = self.verdicts.lock().await;
        if let Some(exists) = verdicts.get(namespace) {
            return Ok(*exists);
        }
        let exists = source.namespace_exists(namespace).await?;
        verdicts.insert(namespace.to_owned(), exists);
        Ok(exists)
    }
}

/// Returns whether this sync is responsible for creating `namespace`.
///
/// Only a `Namespace` manifest in the desired set counts (`in_bundle_namespaces`).
/// `syncOptions.createNamespace` is satisfied by `SyncPlan::pre_create_namespace` /
/// `SyncExecutor::ensure_namespace`, so this set stays narrow to namespaces declared in Git.
fn namespace_is_ours(namespace: &str, in_bundle_namespaces: &[String]) -> bool {
    in_bundle_namespaces
        .iter()
        .any(|declared| declared == namespace)
}

/// De-duplicates requests by key, preserving the first hint set and sorting by key.
fn dedupe(to_fetch: &[FetchRequest]) -> Vec<FetchRequest> {
    let mut unique: BTreeMap<ResourceKey, FetchRequest> = BTreeMap::new();
    for request in to_fetch {
        unique
            .entry(request.key.clone())
            .or_insert_with(|| request.clone());
    }
    unique.into_values().collect()
}

/// Resolves the API resource for `key`, trying each version hint and then any served version.
///
/// Returns `Ok(None)` when the cluster serves no version of that group + kind.
async fn resolve_api(
    discovery: &DiscoveryCache,
    key: &ResourceKey,
    versions: &[String],
) -> Result<Option<(ApiResource, ApiCapabilities)>, LiveStateError> {
    for version in versions {
        let gvk = GroupVersionKind::gvk(&key.group, version, &key.kind);
        match discovery.resolve(&gvk).await {
            Ok(found) => return Ok(Some(found)),
            Err(err) if err.is_no_matches_for_kind() => {}
            Err(err) => return Err(LiveStateError::Discovery(err)),
        }
    }

    // Version-agnostic fallback: identity is GKNN, so any served version of the kind reads the
    // same object (e.g. the manifest pins `v1beta1` but the cluster now only serves `v1`).
    discovery
        .resolve_kind(&key.group, &key.kind)
        .await
        .map_err(LiveStateError::Discovery)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use ferriscd_engine::inventory::InventoryEntry;
    use ferriscd_engine::manifest::DesiredResource;
    use kube::discovery::ApiCapabilities;
    use serde_json::json;

    use super::*;
    use crate::discovery::{DiscoveryFuture, DiscoverySnapshot, DiscoverySource};

    // ---------------------------------------------------------------------
    // Fakes
    // ---------------------------------------------------------------------

    /// What the fake API server answers for one GET.
    // Test fake: the boxed-object ergonomics are not worth it here.
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone, Debug)]
    enum Response {
        Object(DynamicObject),
        Absent,
        ApiError { code: u16, message: String },
    }

    /// Identity of a fetch as the fake observed it.
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct CallKey {
        api_version: String,
        kind: String,
        namespace: Option<String>,
        name: String,
    }

    #[derive(Default)]
    struct FakeSource {
        responses: StdMutex<BTreeMap<CallKey, Response>>,
        namespaces: StdMutex<BTreeSet<String>>,
        calls: StdMutex<Vec<CallKey>>,
        namespace_checks: AtomicUsize,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        yields: usize,
    }

    impl FakeSource {
        fn with_yields(yields: usize) -> Self {
            Self {
                yields,
                ..Self::default()
            }
        }

        fn insert(&self, key: &ResourceKey, version: &str, response: Response) -> &Self {
            self.responses
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    CallKey {
                        api_version: api_version(&key.group, version),
                        kind: key.kind.clone(),
                        namespace: key.namespace.clone(),
                        name: key.name.clone(),
                    },
                    response,
                );
            self
        }

        fn with_namespace(self, namespace: &str) -> Self {
            self.namespaces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(namespace.to_owned());
            self
        }

        fn calls(&self) -> Vec<CallKey> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn namespace_checks(&self) -> usize {
            self.namespace_checks.load(Ordering::SeqCst)
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst)
        }
    }

    impl LiveObjectSource for FakeSource {
        fn get<'a>(&'a self, target: FetchTarget<'a>) -> LiveFuture<'a, Option<DynamicObject>> {
            let call = CallKey {
                api_version: target.api_resource.api_version.clone(),
                kind: target.api_resource.kind.clone(),
                namespace: target.namespace.map(str::to_owned),
                name: target.name.to_owned(),
            };
            if let Ok(mut calls) = self.calls.lock() {
                calls.push(call.clone());
            }
            Box::pin(async move {
                let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
                for _ in 0..self.yields {
                    tokio::task::yield_now().await;
                }
                self.in_flight.fetch_sub(1, Ordering::SeqCst);

                let response = self
                    .responses
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&call)
                    .cloned()
                    // An unscripted GET is a genuine 404 from the fake API server.
                    .unwrap_or(Response::Absent);

                match response {
                    Response::Object(object) => Ok(Some(object)),
                    Response::Absent => Ok(None),
                    Response::ApiError { code, message } => Err(LiveStateError::Api {
                        resource: format!("{}/{}", call.kind, call.name),
                        code,
                        message,
                    }),
                }
            })
        }

        fn namespace_exists<'a>(&'a self, namespace: &'a str) -> LiveFuture<'a, bool> {
            self.namespace_checks.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(self
                    .namespaces
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(namespace))
            })
        }
    }

    #[derive(Default)]
    struct FakeDiscovery {
        snapshot: StdMutex<DiscoverySnapshot>,
    }

    impl FakeDiscovery {
        fn new() -> Self {
            Self {
                snapshot: StdMutex::new(DiscoverySnapshot::new("v1.35.0")),
            }
        }

        fn with(self, group: &str, version: &str, kind: &str, scope: Scope) -> Self {
            {
                let mut snapshot = self
                    .snapshot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                *snapshot = snapshot
                    .clone()
                    .with_resource(api_resource(group, version, kind), capabilities(scope));
            }
            self
        }
    }

    impl DiscoverySource for FakeDiscovery {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(self
                    .snapshot
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone())
            })
        }
    }

    // ---------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------

    fn api_version(group: &str, version: &str) -> String {
        if group.is_empty() {
            version.to_owned()
        } else {
            format!("{group}/{version}")
        }
    }

    fn api_resource(group: &str, version: &str, kind: &str) -> ApiResource {
        let mut resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind));
        // Deterministic plural so the fake's call log matches what discovery reports.
        resource.plural = format!("{}s", kind.to_ascii_lowercase());
        resource
    }

    fn capabilities(scope: Scope) -> ApiCapabilities {
        ApiCapabilities {
            scope,
            subresources: Vec::new(),
            operations: vec!["get".to_owned()],
        }
    }

    /// Builds a fresh (TTL-bounded) discovery cache over a scripted snapshot.
    fn cache(discovery: FakeDiscovery) -> DiscoveryCache {
        DiscoveryCache::with_source(Arc::new(discovery), Duration::from_secs(3600))
    }

    fn key(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> ResourceKey {
        ResourceKey::new(group, kind, namespace.map(str::to_owned), name)
    }

    fn live_object(
        group: &str,
        version: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
        tracking_id: Option<&str>,
    ) -> DynamicObject {
        let mut metadata = json!({ "name": name, "namespace": namespace });
        if let Some(tracking_id) = tracking_id {
            metadata["annotations"] = json!({ "ferriscd.io/tracking-id": tracking_id });
        }
        serde_json::from_value(json!({
            "apiVersion": api_version(group, version),
            "kind": kind,
            "metadata": metadata,
        }))
        .expect("valid DynamicObject")
    }

    fn owner() -> TrackingOwner {
        TrackingOwner::new("ferriscd-system", "payments")
    }

    fn expected(key: &ResourceKey) -> String {
        owner().expected_tracking_id(key)
    }

    fn request(key: ResourceKey, version: &str) -> FetchRequest {
        FetchRequest::new(key, vec![version.to_owned()])
    }

    fn crd_for(group: &str, kind: &str) -> InBundleCrd {
        InBundleCrd {
            group: group.to_owned(),
            kind: kind.to_owned(),
            scope: Scope::Namespaced,
        }
    }

    fn desired_inventory(entries: &[(&ResourceKey, &str)]) -> Inventory {
        entries
            .iter()
            .map(|(key, version)| ((*key).clone(), InventoryEntry::new(*version)))
            .collect()
    }

    // ---------------------------------------------------------------------
    // Classification
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn present_owned_by_self_reports_the_live_object() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default();
        source.insert(
            &configmap,
            "v1",
            Response::Object(live_object(
                "",
                "v1",
                "ConfigMap",
                Some("payments"),
                "settings",
                Some(&expected(&configmap)),
            )),
        );
        let source = Arc::new(source);
        let reader = ClusterStateReader::new(source.clone());
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        let state = states.get(&configmap).expect("one entry");
        assert_eq!(state.ownership(), Some(&Ownership::OwnedBySelf));
        let object = state.object().expect("present");
        assert_eq!(object.metadata.name.as_deref(), Some("settings"));
        assert_eq!(source.calls().len(), 1);
    }

    #[tokio::test]
    async fn present_owned_by_foreign_is_never_adopted() {
        let deployment = key("apps", "Deployment", Some("payments"), "api");
        let foreign = "ferriscd-system/other:apps/Deployment:payments/api";
        let source = FakeSource::default();
        source.insert(
            &deployment,
            "v1",
            Response::Object(live_object(
                "apps",
                "v1",
                "Deployment",
                Some("payments"),
                "api",
                Some(foreign),
            )),
        );
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery =
            cache(FakeDiscovery::new().with("apps", "v1", "Deployment", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(deployment.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        assert_eq!(
            states[&deployment].ownership(),
            Some(&Ownership::OwnedByForeign(foreign.to_owned())),
            "an object owned by another Application must be reported as foreign"
        );
    }

    #[tokio::test]
    async fn present_without_a_tracking_id_is_unmanaged() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default();
        source.insert(
            &configmap,
            "v1",
            Response::Object(live_object(
                "",
                "v1",
                "ConfigMap",
                Some("payments"),
                "settings",
                None,
            )),
        );
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        assert_eq!(states[&configmap].ownership(), Some(&Ownership::Unmanaged));
    }

    #[tokio::test]
    async fn a_404_is_missing_when_the_namespace_exists() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default().with_namespace("payments");
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        assert_eq!(states[&configmap], LiveState::Missing);
        assert!(states[&configmap].is_gone());
        assert!(!states[&configmap].is_deferred());
    }

    #[tokio::test]
    async fn a_410_is_treated_exactly_like_a_404() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default();
        source.insert(
            &configmap,
            "v1",
            Response::ApiError {
                code: 410,
                message: "too old resource version".to_owned(),
            },
        );
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("410 must not fail the fetch");
        assert_eq!(states[&configmap], LiveState::Missing);
    }

    #[tokio::test]
    async fn other_api_errors_are_surfaced_not_swallowed() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default().with_namespace("payments");
        source.insert(
            &configmap,
            "v1",
            Response::ApiError {
                code: 503,
                message: "apiserver is unavailable".to_owned(),
            },
        );
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let err = reader
            .fetch_live(&[request(configmap, "v1")], &discovery, &[], &[], &owner())
            .await
            .expect_err("a 503 must fail the reconcile");

        assert!(
            matches!(err, LiveStateError::Api { code: 503, .. }),
            "{err}"
        );
        assert!(err.is_retryable(), "5xx must retry: {err}");
        assert!(
            err.to_string().contains("apiserver is unavailable"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_forbidden_response_is_terminal_and_names_the_resource() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default();
        source.insert(
            &configmap,
            "v1",
            Response::ApiError {
                code: 403,
                message: "configmaps \"settings\" is forbidden".to_owned(),
            },
        );
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let err = reader
            .fetch_live(&[request(configmap, "v1")], &discovery, &[], &[], &owner())
            .await
            .expect_err("403 must fail the reconcile");
        assert!(!err.is_retryable());
        assert!(err.to_string().contains("ConfigMap/settings"), "{err}");
    }

    #[tokio::test]
    async fn an_unserved_kind_with_an_in_bundle_crd_is_deferred() {
        let widget = key("example.com", "Widget", Some("payments"), "one");
        let reader = ClusterStateReader::new(Arc::new(FakeSource::default()));
        // Discovery does not serve `example.com` at all.
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(widget.clone(), "v1")],
                &discovery,
                &[crd_for("example.com", "Widget")],
                &[],
                &owner(),
            )
            .await
            .expect("a pending CRD must never fail the reconcile");

        assert_eq!(states[&widget], LiveState::DeferredPendingCrd);
        assert!(states[&widget].is_deferred());
    }

    #[tokio::test]
    async fn an_unserved_kind_without_an_in_bundle_crd_is_an_error() {
        let widget = key("example.com", "Widget", Some("payments"), "one");
        let reader = ClusterStateReader::new(Arc::new(FakeSource::default()));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let err = reader
            .fetch_live(&[request(widget, "v1")], &discovery, &[], &[], &owner())
            .await
            .expect_err("an unknown kind must be terminal, not silently missing");

        assert!(matches!(err, LiveStateError::UnknownKind { .. }), "{err}");
        assert!(!err.is_retryable());
        assert!(err.to_string().contains("example.com/Widget"), "{err}");
    }

    #[tokio::test]
    async fn an_orphan_whose_kind_disappeared_is_gone() {
        let widget = key("example.com", "Widget", Some("payments"), "one");
        let reader = ClusterStateReader::new(Arc::new(FakeSource::default()));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(widget.clone(), "v1").as_orphan()],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("a deleted CRD must not fail the reconcile");

        assert_eq!(states[&widget], LiveState::OrphanGvkGone);
        assert!(states[&widget].is_gone());
    }

    #[tokio::test]
    async fn a_404_in_a_namespace_declared_by_the_bundle_is_deferred() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let reader = ClusterStateReader::new(Arc::new(FakeSource::default()));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        // Namespace declared in the bundle and not live yet.
        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &["payments".to_owned()],
                &owner(),
            )
            .await
            .expect("pending namespace must not fail");
        assert_eq!(states[&configmap], LiveState::DeferredPendingNamespace);

        // Without the `Namespace` manifest the same 404 is `Missing`: nothing in v0.2 creates
        // a namespace on demand (`createNamespace: true` is rejected by the pipeline).
        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("a foreign namespace must not fail the fetch");
        assert_eq!(states[&configmap], LiveState::Missing);
    }

    #[tokio::test]
    async fn the_namespace_existence_probe_runs_once_per_namespace_per_pass() {
        // Three keys 404 in the same absent namespace: the pass must probe it once, not three
        // times (a bundle of 50 ConfigMaps in a fresh namespace would otherwise cost 50 extra
        // API calls).
        let source = Arc::new(FakeSource::default());
        let reader = ClusterStateReader::new(source.clone());
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let requests: Vec<FetchRequest> = ["one", "two", "three"]
            .iter()
            .map(|name| request(key("", "ConfigMap", Some("payments"), name), "v1"))
            .collect();

        let states = reader
            .fetch_live(
                &requests,
                &discovery,
                &[],
                &["payments".to_owned()],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        assert_eq!(states.len(), 3);
        assert!(states.values().all(LiveState::is_deferred));
        assert_eq!(
            source.namespace_checks(),
            1,
            "one probe per distinct namespace per pass"
        );

        // A second pass re-probes: the verdict is not cached beyond one pass, so a namespace
        // created by this very sync is visible on the next reconcile.
        reader
            .fetch_live(
                &requests,
                &discovery,
                &[],
                &["payments".to_owned()],
                &owner(),
            )
            .await
            .expect("second pass");
        assert_eq!(source.namespace_checks(), 2);
    }

    #[tokio::test]
    async fn recheck_sees_a_takeover_that_happened_after_the_pass_fetch() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let owned = live_object(
            "",
            "v1",
            "ConfigMap",
            Some("payments"),
            "settings",
            Some(&expected(&configmap)),
        );
        let source = FakeSource::default();
        source.insert(&configmap, "v1", Response::Object(owned));
        let source = Arc::new(source);
        let reader = ClusterStateReader::new(source.clone());
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let first = reader
            .recheck(&configmap, Some("v1"), &discovery, &[], &[], &owner())
            .await
            .expect("recheck must succeed");
        assert_eq!(first.ownership(), Some(&Ownership::OwnedBySelf));

        // Another Application takes the object over between the pass fetch and the delete.
        let foreign = "ferriscd-system/other:/ConfigMap:payments/settings";
        source.insert(
            &configmap,
            "v1",
            Response::Object(live_object(
                "",
                "v1",
                "ConfigMap",
                Some("payments"),
                "settings",
                Some(foreign),
            )),
        );
        let again = reader
            .recheck(&configmap, Some("v1"), &discovery, &[], &[], &owner())
            .await
            .expect("recheck must succeed");
        assert_eq!(
            again.ownership(),
            Some(&Ownership::OwnedByForeign(foreign.to_owned())),
            "a re-check must not resurrect the stale verdict"
        );

        // An object that vanished in between is a confirmed absence, not an error.
        source.insert(&configmap, "v1", Response::Absent);
        assert_eq!(
            reader
                .recheck(&configmap, Some("v1"), &discovery, &[], &[], &owner())
                .await
                .expect("recheck must succeed"),
            LiveState::Missing
        );
        assert_eq!(
            source.namespace_checks(),
            0,
            "a re-check must not probe namespaces it was not asked about"
        );
    }

    #[tokio::test]
    async fn a_404_in_a_namespace_that_already_exists_is_missing() {
        // The self-heal case: the bundle declares the Namespace and it is already live, so a
        // 404 on the object means the object was deleted and must be re-created — not looped
        // forever as "namespace pending".
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default().with_namespace("payments");
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &["payments".to_owned()],
                &owner(),
            )
            .await
            .expect("fetch must succeed");
        assert_eq!(states[&configmap], LiveState::Missing);
    }

    #[tokio::test]
    async fn a_404_in_a_foreign_namespace_is_missing_without_probing_it() {
        // `payments` is not created by this sync, so the reader must not invent a pending
        // namespace and must not spend an extra API call probing it.
        let configmap = key("", "ConfigMap", Some("other"), "settings");
        let source = Arc::new(FakeSource::default());
        let reader = ClusterStateReader::new(source.clone());
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[request(configmap.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");
        assert_eq!(states[&configmap], LiveState::Missing);
        assert_eq!(source.namespace_checks(), 0);
    }

    #[tokio::test]
    async fn cluster_scoped_resources_are_fetched_cluster_wide() {
        let cluster_role = key("rbac.authorization.k8s.io", "ClusterRole", None, "reader");
        let source = FakeSource::default();
        source.insert(
            &cluster_role,
            "v1",
            Response::Object(live_object(
                "rbac.authorization.k8s.io",
                "v1",
                "ClusterRole",
                None,
                "reader",
                Some(&expected(&cluster_role)),
            )),
        );
        let source = Arc::new(source);
        let reader = ClusterStateReader::new(source.clone());
        let discovery = cache(FakeDiscovery::new().with(
            "rbac.authorization.k8s.io",
            "v1",
            "ClusterRole",
            Scope::Cluster,
        ));

        let states = reader
            .fetch_live(
                &[request(cluster_role.clone(), "v1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        assert!(states[&cluster_role].is_present());
        let calls = source.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].namespace, None,
            "a cluster-scoped object must never be fetched through a namespace"
        );
    }

    #[tokio::test]
    async fn a_version_hint_that_is_not_served_falls_back_to_the_served_version() {
        // Identity is GKNN: the manifest pins `v1beta1`, the cluster only serves `v1`.
        let ingress = key("networking.k8s.io", "Ingress", Some("payments"), "web");
        let source = FakeSource::default();
        source.insert(
            &ingress,
            "v1",
            Response::Object(live_object(
                "networking.k8s.io",
                "v1",
                "Ingress",
                Some("payments"),
                "web",
                Some(&expected(&ingress)),
            )),
        );
        let source = Arc::new(source);
        let reader = ClusterStateReader::new(source.clone());
        let discovery = cache(FakeDiscovery::new().with(
            "networking.k8s.io",
            "v1",
            "Ingress",
            Scope::Namespaced,
        ));

        let states = reader
            .fetch_live(
                &[request(ingress.clone(), "v1beta1")],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        assert_eq!(states[&ingress].ownership(), Some(&Ownership::OwnedBySelf));
        assert_eq!(source.calls()[0].api_version, "networking.k8s.io/v1");
    }

    #[tokio::test]
    async fn a_namespaced_key_without_a_namespace_is_a_scope_mismatch() {
        let configmap = key("", "ConfigMap", None, "settings");
        let reader = ClusterStateReader::new(Arc::new(FakeSource::default()));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let err = reader
            .fetch_live(&[request(configmap, "v1")], &discovery, &[], &[], &owner())
            .await
            .expect_err("an inconsistent key must be reported");
        assert!(matches!(err, LiveStateError::ScopeMismatch { .. }), "{err}");
        assert!(!err.is_retryable());
    }

    // ---------------------------------------------------------------------
    // Determinism, de-duplication and boundedness
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn results_are_ordered_by_resource_key_and_stable_across_runs() {
        let keys = vec![
            key("apps", "Deployment", Some("payments"), "api"),
            key("", "Namespace", None, "team-a"),
            key("", "ConfigMap", Some("payments"), "settings"),
        ];
        let source = FakeSource::with_yields(2);
        for key in &keys {
            let version = "v1";
            source.insert(
                key,
                version,
                Response::Object(live_object(
                    &key.group,
                    version,
                    &key.kind,
                    key.namespace.as_deref(),
                    &key.name,
                    Some(&expected(key)),
                )),
            );
        }
        let reader = ClusterStateReader::new(Arc::new(source));
        let discovery = cache(
            FakeDiscovery::new()
                .with("", "v1", "Namespace", Scope::Cluster)
                .with("", "v1", "ConfigMap", Scope::Namespaced)
                .with("apps", "v1", "Deployment", Scope::Namespaced),
        );

        let mut requests: Vec<FetchRequest> =
            keys.iter().map(|key| request(key.clone(), "v1")).collect();
        // Reverse the input: the output order must not depend on it.
        requests.reverse();

        let first = reader
            .fetch_live(&requests, &discovery, &[], &[], &owner())
            .await
            .expect("fetch must succeed");
        let second = reader
            .fetch_live(&requests, &discovery, &[], &[], &owner())
            .await
            .expect("fetch must succeed");

        let order: Vec<&ResourceKey> = first.keys().collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted, "the result must be ordered by ResourceKey");
        assert_eq!(first, second, "two passes must agree byte for byte");
        assert_eq!(first.len(), keys.len());
    }

    #[tokio::test]
    async fn duplicate_keys_are_fetched_once() {
        let configmap = key("", "ConfigMap", Some("payments"), "settings");
        let source = FakeSource::default().with_namespace("payments");
        source.insert(
            &configmap,
            "v1",
            Response::Object(live_object(
                "",
                "v1",
                "ConfigMap",
                Some("payments"),
                "settings",
                Some(&expected(&configmap)),
            )),
        );
        let source = Arc::new(source);
        let reader = ClusterStateReader::new(source.clone());
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));

        let states = reader
            .fetch_live(
                &[
                    request(configmap.clone(), "v1"),
                    request(configmap.clone(), "v1"),
                    FetchRequest::new(configmap.clone(), vec!["v1".to_owned()]),
                ],
                &discovery,
                &[],
                &[],
                &owner(),
            )
            .await
            .expect("fetch must succeed");

        assert_eq!(states.len(), 1);
        assert_eq!(
            source.calls().len(),
            1,
            "duplicate keys must be fetched exactly once"
        );
    }

    #[tokio::test]
    async fn concurrency_is_bounded_by_the_documented_limit() {
        const REQUESTS: usize = 64;

        let source = Arc::new(FakeSource::with_yields(3));
        let discovery = cache(FakeDiscovery::new().with("", "v1", "ConfigMap", Scope::Namespaced));
        let reader = ClusterStateReader::new(source.clone());

        let requests: Vec<FetchRequest> = (0..REQUESTS)
            .map(|index| {
                request(
                    key(
                        "",
                        "ConfigMap",
                        Some("payments"),
                        &format!("settings-{index}"),
                    ),
                    "v1",
                )
            })
            .collect();

        let states = reader
            .fetch_live(&requests, &discovery, &[], &[], &owner())
            .await
            .expect("fetch must succeed");

        assert_eq!(states.len(), REQUESTS);
        assert_eq!(source.calls().len(), REQUESTS);
        assert_eq!(
            source.max_in_flight(),
            LIVE_FETCH_CONCURRENCY,
            "the reader must saturate exactly {LIVE_FETCH_CONCURRENCY} in-flight fetches: fewer              means it is serializing, more means the bound leaked"
        );
    }

    // ---------------------------------------------------------------------
    // Plan / owner helpers
    // ---------------------------------------------------------------------

    #[test]
    fn plan_fetch_is_the_union_with_desired_versions_preferred() {
        let deployment = key("apps", "Deployment", Some("payments"), "api");
        let removed = key("", "Service", Some("payments"), "api");

        let desired = desired_inventory(&[(&deployment, "v1")]);
        let previous = desired_inventory(&[(&deployment, "v1beta1"), (&removed, "v1")]);

        let plan = plan_fetch(&desired, &previous);
        assert_eq!(
            plan.iter()
                .map(|request| request.key.clone())
                .collect::<Vec<_>>(),
            vec![removed.clone(), deployment.clone()],
            "plan must be the sorted union of desired and previous inventory"
        );

        let deployment_request = &plan[1];
        assert_eq!(
            deployment_request.versions,
            vec!["v1".to_owned(), "v1beta1".to_owned()],
            "the desired version must be tried before the inventory hint"
        );
        assert!(!deployment_request.orphan);

        let removed_request = &plan[0];
        assert!(removed_request.orphan, "previous-only keys are orphans");
        assert_eq!(removed_request.versions, vec!["v1".to_owned()]);

        // An empty desired set makes every previous key an orphan (trap T1: still fetched).
        let plan = plan_fetch(&Inventory::new(), &previous);
        assert_eq!(plan.len(), 2);
        assert!(plan.iter().all(|request| request.orphan));
    }

    #[test]
    fn fetch_requests_tolerate_missing_version_hints() {
        let empty = FetchRequest::new(
            key("", "ConfigMap", Some("payments"), "settings"),
            Vec::new(),
        );
        assert!(empty.versions.is_empty());

        let mut request = empty.clone();
        request.push_version("   ");
        request.push_version("");
        assert!(request.versions.is_empty(), "blank hints are ignored");

        request.push_version("v1");
        request.push_version("v1");
        assert_eq!(request.versions, vec!["v1".to_owned()], "hints are unique");
    }

    #[test]
    fn tracking_owner_needs_an_application_namespace() {
        use ferriscd_crd::{
            ApplicationSpec, DestinationSpec, GitSourceSpec, RendererSpec, SourceSpec,
        };

        let spec = ApplicationSpec {
            project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: SourceSpec {
                git: GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "HEAD".to_owned(),
                    path: String::new(),
                },
                renderer: RendererSpec::default(),
            },
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: 180,
            revision_history_limit: 10,
        };

        let mut app = Application::new("demo", spec);
        assert_eq!(TrackingOwner::for_application(&app), None);

        app.metadata.namespace = Some("ferriscd-system".to_owned());
        let owner = TrackingOwner::for_application(&app).expect("namespaced application");
        assert_eq!(owner.namespace, "ferriscd-system");
        assert_eq!(owner.name, "demo");
        assert_eq!(
            owner.expected_tracking_id(&key("apps", "Deployment", Some("payments"), "api")),
            "ferriscd-system/demo:apps/Deployment:payments/api"
        );
    }

    /// `LiveState` helpers must be consistent with the variants they describe.
    #[test]
    fn live_state_helpers_agree_with_their_variants() {
        let object = live_object("", "v1", "ConfigMap", Some("payments"), "settings", None);
        let present = LiveState::Present(Box::new(object.clone()), Ownership::Unmanaged);
        assert!(present.is_present());
        assert!(!present.is_deferred());
        assert!(!present.is_gone());
        assert_eq!(present.object(), Some(&object));

        for state in [LiveState::Missing, LiveState::OrphanGvkGone] {
            assert!(state.is_gone());
            assert!(!state.is_present());
            assert!(!state.is_deferred());
            assert_eq!(state.ownership(), None);
        }

        for state in [
            LiveState::DeferredPendingCrd,
            LiveState::DeferredPendingNamespace,
        ] {
            assert!(state.is_deferred());
            assert!(!state.is_gone());
            assert!(!state.is_present());
        }
    }

    /// A `DesiredResource` is not required by the reader, but the request builder must stay
    /// compatible with how the pipeline derives desired versions.
    #[test]
    fn plan_fetch_prefers_desired_resource_versions() {
        let resource = DesiredResource {
            key: key("networking.k8s.io", "Ingress", Some("payments"), "web"),
            gvk: ferriscd_engine::manifest::GroupVersionKind::parse(
                "networking.k8s.io/v1beta1",
                "Ingress",
            )
            .expect("gvk"),
            object: live_object(
                "networking.k8s.io",
                "v1beta1",
                "Ingress",
                Some("payments"),
                "web",
                None,
            ),
            source_file: "ingress.yaml".to_owned(),
        };
        let desired = desired_inventory(&[(&resource.key, &resource.gvk.version)]);
        let previous = desired_inventory(&[(&resource.key, "v1")]);

        let plan = plan_fetch(&desired, &previous);
        assert_eq!(
            plan[0].versions,
            vec!["v1beta1".to_owned(), "v1".to_owned()]
        );
    }
}
