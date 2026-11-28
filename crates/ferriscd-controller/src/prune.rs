//! Ownership-verified, TOCTOU-safe pruning (T08.5).
//!
//! Deleting is the highest-blast-radius thing a GitOps controller does, so this module is
//! deliberately paranoid. Before every single `Delete`:
//!
//! 1. **Re-GET the live object.** The pass-level [`LiveStateMap`](crate::live_state::LiveStateMap) was read before the diff, the
//!    plan and possibly dozens of applies; an object can be taken over, relabelled or deleted in
//!    that window. A `404`/`410` here is a *confirmed absence* and counts as a successful prune
//!    (nothing is issued), never as an error.
//! 2. **Re-verify `ferriscd.io/tracking-id`.** Only an exact match with this `Application`'s
//!    identifier may be deleted (trap T10). A foreign or missing annotation retains the object,
//!    reports why, and leaves it in `status.inventory` so the conflict stays visible.
//! 3. **Re-check the safety rails.** `ferriscd.io/prune: "false"`, `CustomResourceDefinition` and
//!    `Namespace` are re-evaluated on the *fresh* object (the operator may have added the opt-out
//!    a second ago). CRDs and namespaces need `syncOptions.pruneCRDs`/`pruneNamespaces` — the
//!    catastrophic auto-prune of finding H3 is opt-in only.
//! 4. **Delete with `DeleteParams::background()`**, so the API server owns garbage collection and
//!    the controller never blocks a worker waiting for finalizers.
//!
//! A failed delete is returned as an error: the caller persists the inventory **without** the
//! key, so the orphan is retried on the next reconcile instead of leaking (finding C1).
//!
//! The same pruner is used by the cascade finalizer path (`ferriscd.io/cascade-delete: "true"`),
//! so deleting an `Application` can never delete more than a prune would.

use ferriscd_crd::{SyncOptions, annotations};
use ferriscd_engine::graph::order::{is_crd_key, is_namespace_key};
use ferriscd_engine::inventory::Ownership;
use ferriscd_engine::manifest::ResourceKey;
use futures::future::BoxFuture;
use kube::api::DynamicObject;
use kube::discovery::Scope;
use tracing::warn;

use crate::discovery::DiscoveryCache;
use crate::live_state::{ClusterStateReader, LiveState, TrackingOwner};
use crate::reconcile::ReconcileError;
use crate::sync::{Applier, DeleteOutcome, DeleteRequest};
use crate::sync_executor::resolve_key_target;

/// Why an orphan was deliberately kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainReason {
    /// The live object carries another `Application`'s `ferriscd.io/tracking-id` (trap T10).
    ForeignOwner {
        /// The foreign identifier, exactly as recorded.
        owner: String,
    },
    /// The live object carries no tracking annotation: FerrisCD never deletes what it cannot
    /// prove it created.
    Unmanaged,
    /// `ferriscd.io/prune: "false"` on the live object.
    PruneOptedOut,
    /// Safety rail (finding H3): `CustomResourceDefinition` pruning needs `pruneCRDs`.
    CrdPruneDisabled,
    /// Safety rail (finding H3): `Namespace` pruning needs `pruneNamespaces`.
    NamespacePruneDisabled,
    /// The live state could not be classified this pass (deferred on a CRD/namespace).
    Deferred,
}

impl RetainReason {
    /// Stable label used in logs.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ForeignOwner { .. } => "ownedByForeign",
            Self::Unmanaged => "unmanaged",
            Self::PruneOptedOut => "pruneOptedOut",
            Self::CrdPruneDisabled => "crdPruneDisabled",
            Self::NamespacePruneDisabled => "namespacePruneDisabled",
            Self::Deferred => "deferred",
        }
    }
}

impl std::fmt::Display for RetainReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignOwner { owner } => {
                write!(f, "owned by another Application ({owner})")
            }
            Self::Unmanaged => f.write_str("no ferriscd.io/tracking-id: not ours to delete"),
            Self::PruneOptedOut => f.write_str("live object carries ferriscd.io/prune=false"),
            Self::CrdPruneDisabled => {
                f.write_str("CustomResourceDefinition pruning needs syncOptions.pruneCRDs")
            }
            Self::NamespacePruneDisabled => {
                f.write_str("Namespace pruning needs syncOptions.pruneNamespaces")
            }
            Self::Deferred => f.write_str("live state is deferred on a CRD or namespace"),
        }
    }
}

/// Outcome of one prune attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PruneResult {
    /// The object is gone: either the delete was accepted, or it was already absent
    /// (`404`/`410`, `NoMatchesForKind`). Either way the inventory entry may be dropped.
    Pruned,
    /// The object was deliberately kept; `status.inventory` keeps tracking it.
    Retained(RetainReason),
}

impl PruneResult {
    /// Returns whether the object is confirmed gone.
    #[must_use]
    pub fn is_pruned(&self) -> bool {
        matches!(self, Self::Pruned)
    }
}

/// Returns whether `object` carries `ferriscd.io/prune: "false"`.
///
/// Split out of [`prune_rail`] because the planner has to know the opt-out *before* it knows the
/// `syncOptions` rails (it classifies the orphan from the pass-level live read).
#[must_use]
pub fn prune_opted_out(object: &DynamicObject) -> bool {
    object
        .metadata
        .annotations
        .as_ref()
        .and_then(|map| map.get(annotations::PRUNE))
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("false"))
}

/// Returns why `object` may not be deleted, or `None` when the rails allow it.
///
/// Pure: the CRD/namespace rails live in one place so the planner, the pruner and the finalizer
/// cannot disagree (finding H3).
#[must_use]
pub fn prune_rail(
    key: &ResourceKey,
    options: &SyncOptions,
    object: &DynamicObject,
) -> Option<RetainReason> {
    if prune_opted_out(object) {
        return Some(RetainReason::PruneOptedOut);
    }
    if is_crd_key(key) && !options.prune_crds {
        return Some(RetainReason::CrdPruneDisabled);
    }
    if is_namespace_key(key) && !options.prune_namespaces {
        return Some(RetainReason::NamespacePruneDisabled);
    }
    None
}

/// Deleting one object after re-verifying ownership.
///
/// A trait object so the executor and the finalizer share exactly one implementation, and tests
/// can script prune outcomes without a cluster.
pub trait ResourcePruner: Send + Sync {
    /// Deletes `key` if — and only if — it is still verifiably ours.
    fn prune<'a>(
        &'a self,
        key: &'a ResourceKey,
        version_hint: Option<&'a str>,
    ) -> BoxFuture<'a, Result<PruneResult, ReconcileError>>;
}

/// [`ResourcePruner`] that re-reads and re-verifies before every delete.
pub struct OwnershipVerifiedPruner<'a> {
    applier: &'a dyn Applier,
    reader: &'a ClusterStateReader,
    discovery: &'a DiscoveryCache,
    owner: &'a TrackingOwner,
    options: &'a SyncOptions,
}

impl std::fmt::Debug for OwnershipVerifiedPruner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnershipVerifiedPruner")
            .field("owner", &self.owner)
            .field("options", self.options)
            .finish_non_exhaustive()
    }
}

impl<'a> OwnershipVerifiedPruner<'a> {
    /// Builds a pruner for one reconcile pass.
    #[must_use]
    pub fn new(
        applier: &'a dyn Applier,
        reader: &'a ClusterStateReader,
        discovery: &'a DiscoveryCache,
        owner: &'a TrackingOwner,
        options: &'a SyncOptions,
    ) -> Self {
        Self {
            applier,
            reader,
            discovery,
            owner,
            options,
        }
    }

    /// Deletes one previously managed object, or explains why it was kept.
    ///
    /// # Errors
    ///
    /// Returns [`ReconcileError::Delete`] (or a discovery/live-state error) when the delete could
    /// not be confirmed. The caller must then keep the key in `status.inventory` so the next
    /// reconcile retries it.
    pub async fn prune(
        &self,
        key: &ResourceKey,
        version_hint: Option<&str>,
    ) -> Result<PruneResult, ReconcileError> {
        // A kind that no longer exists means nothing is left to delete (finding C2: identity is
        // version-agnostic, so this is the normal outcome of a CRD removal).
        let Some(target) = resolve_key_target(self.discovery, key, version_hint).await? else {
            return Ok(PruneResult::Pruned);
        };
        let namespace = match target.scope {
            Scope::Namespaced => key.namespace.clone(),
            Scope::Cluster => None,
        };

        // TOCTOU: never trust the pass-level verdict for a delete.
        let rechecked = self
            .reader
            .recheck(
                key,
                Some(target.api_resource.version.as_str()),
                self.discovery,
                &[],
                &[],
                self.owner,
            )
            .await?;

        match rechecked {
            // Confirmed absence — `404`/`410` counts as a confirmed prune (MASTER_PLAN §4.3).
            LiveState::Missing | LiveState::OrphanGvkGone => Ok(PruneResult::Pruned),
            LiveState::Present(fresh, Ownership::OwnedBySelf) => {
                if let Some(reason) = prune_rail(key, self.options, &fresh) {
                    warn!(
                        resource = %key.canonical(),
                        reason = reason.as_str(),
                        "refusing to prune: a safety rail applies to the live object"
                    );
                    return Ok(PruneResult::Retained(reason));
                }
                match self
                    .applier
                    .delete(DeleteRequest {
                        key,
                        api_resource: &target.api_resource,
                        namespace: namespace.as_deref(),
                    })
                    .await?
                {
                    // `AlreadyGone` is a `404`/`410` from the delete itself: still confirmed, and
                    // still a delete FerrisCD issued — so the caller records a prune marker for it
                    // exactly like a `Deleted` (finding N-5: `ReplaceRecovery` follows the same
                    // rule, so "a marker exists for every delete we issued" holds on both paths).
                    DeleteOutcome::Deleted | DeleteOutcome::AlreadyGone => Ok(PruneResult::Pruned),
                }
            }
            LiveState::Present(_, Ownership::OwnedByForeign(owner)) => {
                warn!(
                    resource = %key.canonical(),
                    foreign_owner = %owner,
                    "refusing to prune: the object was taken over by another Application between \
                     the live read and the delete"
                );
                Ok(PruneResult::Retained(RetainReason::ForeignOwner { owner }))
            }
            LiveState::Present(_, Ownership::Unmanaged) => {
                warn!(
                    resource = %key.canonical(),
                    "refusing to prune: the object has no ferriscd.io/tracking-id"
                );
                Ok(PruneResult::Retained(RetainReason::Unmanaged))
            }
            LiveState::DeferredPendingCrd | LiveState::DeferredPendingNamespace => {
                Ok(PruneResult::Retained(RetainReason::Deferred))
            }
        }
    }
}

impl ResourcePruner for OwnershipVerifiedPruner<'_> {
    fn prune<'a>(
        &'a self,
        key: &'a ResourceKey,
        version_hint: Option<&'a str>,
    ) -> BoxFuture<'a, Result<PruneResult, ReconcileError>> {
        Box::pin(async move { OwnershipVerifiedPruner::prune(self, key, version_hint).await })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex as StdMutex};

    use ferriscd_engine::graph::order::sort_keys_prune_order;
    use kube::api::ApiResource;
    use kube::core::GroupVersionKind as KubeGvk;
    use kube::discovery::ApiCapabilities;
    use serde_json::json;

    use super::*;
    use crate::discovery::{DiscoveryFuture, DiscoverySnapshot, DiscoverySource};
    use crate::live_state::{FetchTarget, LiveFuture, LiveObjectSource, LiveStateError};
    use crate::sync::ApplyRequest;

    const OWNER_NAMESPACE: &str = "ferriscd-system";
    const OWNER_NAME: &str = "payments";
    const NAMESPACE: &str = "payments";

    /// Scripted API server: live objects, deletes and delete failures.
    #[derive(Default)]
    struct FakeCluster {
        objects: StdMutex<BTreeMap<String, DynamicObject>>,
        deletes: StdMutex<Vec<String>>,
        /// Deletes that fail with an API error.
        failing_deletes: StdMutex<BTreeMap<String, u16>>,
        /// Deletes the API server answers with `404`/`410` (`DeleteOutcome::AlreadyGone`).
        already_gone: StdMutex<bool>,
    }

    impl FakeCluster {
        fn with_object(self, object: DynamicObject) -> Self {
            self.objects.lock().unwrap().insert(gknn(&object), object);
            self
        }

        fn failing_delete(self, gknn: &str, code: u16) -> Self {
            self.failing_deletes
                .lock()
                .unwrap()
                .insert(gknn.to_owned(), code);
            self
        }

        /// Every delete answers `AlreadyGone`: the object vanished before the delete landed.
        fn answering_already_gone(self) -> Self {
            *self.already_gone.lock().unwrap() = true;
            self
        }

        fn deletes(&self) -> Vec<String> {
            self.deletes.lock().unwrap().clone()
        }
    }

    fn gknn(object: &DynamicObject) -> String {
        let api_version = object
            .types
            .as_ref()
            .map(|types| types.api_version.clone())
            .unwrap_or_default();
        let kind = object
            .types
            .as_ref()
            .map(|types| types.kind.clone())
            .unwrap_or_default();
        let group = api_version
            .split_once('/')
            .map(|(group, _)| group)
            .unwrap_or("");
        format!(
            "{group}/{kind}/{}/{}",
            object.metadata.namespace.as_deref().unwrap_or_default(),
            object.metadata.name.as_deref().unwrap_or_default()
        )
    }

    impl LiveObjectSource for FakeCluster {
        fn get<'a>(&'a self, target: FetchTarget<'a>) -> LiveFuture<'a, Option<DynamicObject>> {
            let wanted = format!(
                "{}/{}/{}/{}",
                target.api_resource.group,
                target.api_resource.kind,
                target.namespace.unwrap_or_default(),
                target.name
            );
            let object = self.objects.lock().unwrap().get(&wanted).cloned();
            Box::pin(async move { Ok(object) })
        }

        fn namespace_exists<'a>(&'a self, _namespace: &'a str) -> LiveFuture<'a, bool> {
            Box::pin(async { Ok(true) })
        }
    }

    impl Applier for FakeCluster {
        fn apply<'a>(
            &'a self,
            _request: ApplyRequest<'a>,
        ) -> BoxFuture<'a, Result<DynamicObject, ReconcileError>> {
            Box::pin(async {
                Err(ReconcileError::Invalid {
                    message: "the pruner must never apply".to_owned(),
                })
            })
        }

        fn delete<'a>(
            &'a self,
            request: DeleteRequest<'a>,
        ) -> BoxFuture<'a, Result<DeleteOutcome, ReconcileError>> {
            let key = request.key.canonical();
            Box::pin(async move {
                self.deletes.lock().unwrap().push(key.clone());
                if let Some(code) = self.failing_deletes.lock().unwrap().get(&key).copied() {
                    // Mirrors `DynamicApiApplier::delete`: the error names the resource.
                    return Err(ReconcileError::Delete {
                        resource: key,
                        source: kube::Error::Api(
                            kube::core::Status::failure("nope", "InternalError")
                                .with_code(code)
                                .boxed(),
                        ),
                    });
                }
                self.objects.lock().unwrap().remove(&key);
                if *self.already_gone.lock().unwrap() {
                    return Ok(DeleteOutcome::AlreadyGone);
                }
                Ok(DeleteOutcome::Deleted)
            })
        }
    }

    #[derive(Default)]
    struct FakeDiscovery {
        snapshot: StdMutex<DiscoverySnapshot>,
        fetches: StdMutex<usize>,
    }

    impl FakeDiscovery {
        fn with_kinds() -> Self {
            let mut snapshot = DiscoverySnapshot::new("v1.35.0");
            for (group, kind, scope) in [
                ("", "ConfigMap", Scope::Namespaced),
                ("", "Namespace", Scope::Cluster),
                (
                    "apiextensions.k8s.io",
                    "CustomResourceDefinition",
                    Scope::Cluster,
                ),
            ] {
                let mut resource = ApiResource::from_gvk(&KubeGvk::gvk(group, "v1", kind));
                resource.plural = format!("{}s", kind.to_ascii_lowercase());
                snapshot = snapshot.with_resource(
                    resource,
                    ApiCapabilities {
                        scope,
                        subresources: Vec::new(),
                        operations: vec!["get".to_owned(), "delete".to_owned()],
                    },
                );
            }
            Self {
                snapshot: StdMutex::new(snapshot),
                fetches: StdMutex::new(0),
            }
        }

        fn drop_kind(&self, group: &str, kind: &str) {
            let mut snapshot = DiscoverySnapshot::new("v1.35.0");
            for (existing_group, existing_kind, scope) in [
                ("", "ConfigMap", Scope::Namespaced),
                ("", "Namespace", Scope::Cluster),
                (
                    "apiextensions.k8s.io",
                    "CustomResourceDefinition",
                    Scope::Cluster,
                ),
            ] {
                if existing_group == group && existing_kind == kind {
                    continue;
                }
                let mut resource =
                    ApiResource::from_gvk(&KubeGvk::gvk(existing_group, "v1", existing_kind));
                resource.plural = format!("{}s", existing_kind.to_ascii_lowercase());
                snapshot = snapshot.with_resource(
                    resource,
                    ApiCapabilities {
                        scope,
                        subresources: Vec::new(),
                        operations: Vec::new(),
                    },
                );
            }
            *self.snapshot.lock().unwrap() = snapshot;
        }

        fn fetches(&self) -> usize {
            *self.fetches.lock().unwrap()
        }
    }

    impl DiscoverySource for FakeDiscovery {
        fn fetch(&self) -> DiscoveryFuture<'_> {
            Box::pin(async move {
                *self.fetches.lock().unwrap() += 1;
                Ok(self.snapshot.lock().unwrap().clone())
            })
        }
    }

    struct Fixture {
        cluster: Arc<FakeCluster>,
        discovery: Arc<FakeDiscovery>,
        cache: DiscoveryCache,
        reader: ClusterStateReader,
        owner: TrackingOwner,
    }

    fn fixture(cluster: FakeCluster) -> Fixture {
        let cluster = Arc::new(cluster);
        let discovery = Arc::new(FakeDiscovery::with_kinds());
        let cache =
            DiscoveryCache::with_source(discovery.clone(), std::time::Duration::from_secs(3600));
        Fixture {
            cluster: cluster.clone(),
            discovery,
            cache,
            reader: ClusterStateReader::new(cluster),
            owner: TrackingOwner::new(OWNER_NAMESPACE, OWNER_NAME),
        }
    }

    impl Fixture {
        fn pruner<'a>(&'a self, options: &'a SyncOptions) -> OwnershipVerifiedPruner<'a> {
            let applier: &dyn Applier = &*self.cluster;
            OwnershipVerifiedPruner::new(applier, &self.reader, &self.cache, &self.owner, options)
        }
    }

    fn tracking_id(kind: &str, name: &str) -> String {
        format!("{OWNER_NAMESPACE}/{OWNER_NAME}:/{kind}:{NAMESPACE}/{name}")
    }

    fn config_map(
        name: &str,
        tracking: Option<&str>,
        annotations: Option<serde_json::Value>,
    ) -> DynamicObject {
        let mut annotation_map = serde_json::Map::new();
        if let Some(tracking) = tracking {
            annotation_map.insert(annotations::TRACKING_ID.to_owned(), json!(tracking));
        }
        if let Some(extra) = annotations
            && let Some(extra) = extra.as_object()
        {
            for (key, value) in extra {
                annotation_map.insert(key.clone(), value.clone());
            }
        }
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": name, "namespace": NAMESPACE, "annotations": annotation_map },
        }))
        .unwrap()
    }

    fn crd(name: &str, tracking: &str) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {
                "name": name,
                "annotations": { annotations::TRACKING_ID: tracking },
            },
        }))
        .unwrap()
    }

    fn namespace_object(name: &str, tracking: &str) -> DynamicObject {
        serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": name,
                "annotations": { annotations::TRACKING_ID: tracking },
            },
        }))
        .unwrap()
    }

    fn removed_key(name: &str) -> ResourceKey {
        ResourceKey::new("", "ConfigMap", Some(NAMESPACE.to_owned()), name)
    }

    // ------------------------------------------------------------------
    // Happy path and the confirmed-absence cases
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn an_owned_orphan_is_deleted_once() {
        let fixture = fixture(FakeCluster::default().with_object(config_map(
            "removed",
            Some(&tracking_id("ConfigMap", "removed")),
            None,
        )));
        let options = SyncOptions::default();

        let result = fixture
            .pruner(&options)
            .prune(&removed_key("removed"), Some("v1"))
            .await
            .expect("prune must succeed");

        assert_eq!(result, PruneResult::Pruned);
        assert_eq!(
            fixture.cluster.deletes(),
            vec!["/ConfigMap/payments/removed".to_owned()],
            "exactly one delete may be issued"
        );
    }

    #[tokio::test]
    async fn a_missing_object_counts_as_pruned_without_a_delete_call() {
        let fixture = fixture(FakeCluster::default());
        let options = SyncOptions::default();

        let result = fixture
            .pruner(&options)
            .prune(&removed_key("gone"), Some("v1"))
            .await
            .expect("an absent object is not an error");
        assert_eq!(result, PruneResult::Pruned, "404 is a confirmed prune");
        assert!(
            fixture.cluster.deletes().is_empty(),
            "a 404 must not produce a pointless delete"
        );
    }

    #[tokio::test]
    async fn an_unserved_kind_counts_as_pruned() {
        // The CRD is gone, so the custom resource went with it (finding C2).
        let fixture = fixture(FakeCluster::default());
        fixture.discovery.drop_kind("example.com", "Widget");
        let options = SyncOptions::default();
        let key = ResourceKey::new("example.com", "Widget", Some(NAMESPACE.to_owned()), "one");

        assert_eq!(
            fixture
                .pruner(&options)
                .prune(&key, Some("v1"))
                .await
                .expect("prune"),
            PruneResult::Pruned
        );
        assert!(fixture.cluster.deletes().is_empty());
        assert_eq!(
            fixture.discovery.fetches(),
            1,
            "resolution must consult discovery exactly once"
        );
    }

    // ------------------------------------------------------------------
    // Finding N-5: the confirmed-absence result the `Replace` path must match
    // ------------------------------------------------------------------

    /// **Finding N-5 (the rule `ReplaceRecovery` mirrors):** a delete the API server answers with
    /// `404`/`410` is still a delete FerrisCD issued, so it is a confirmed prune.
    ///
    /// Both delete paths must agree: the executor records a prune marker for exactly
    /// `PruneResult::Pruned`, so an `AlreadyGone` here must not turn into a `Retained`/error — that
    /// would leave the `Delete` event of our own prune looking like an out-of-band delete (the event
    /// repeats the last written `resourceVersion`). `ReplaceRecovery::replace` follows the same rule
    /// for the delete a `Replace=true` issues.
    #[tokio::test]
    async fn an_already_gone_delete_is_a_confirmed_prune() {
        let fixture = fixture(
            FakeCluster::default()
                .with_object(config_map(
                    "removed",
                    Some(&tracking_id("ConfigMap", "removed")),
                    None,
                ))
                .answering_already_gone(),
        );
        let options = SyncOptions::default();

        let result = fixture
            .pruner(&options)
            .prune(&removed_key("removed"), Some("v1"))
            .await
            .expect("a 404/410 from the delete itself is not an error");

        assert_eq!(
            result,
            PruneResult::Pruned,
            "an AlreadyGone delete is a delete FerrisCD issued, exactly like a 200"
        );
        assert_eq!(
            fixture.cluster.deletes(),
            vec!["/ConfigMap/payments/removed".to_owned()],
            "the delete must have been issued exactly once"
        );
    }

    // ------------------------------------------------------------------
    // Trap guards: ownership and rails
    // ------------------------------------------------------------------

    /// **Trap guard (T10):** a foreign owner is never deleted, even though the pass-level fetch
    /// may have said otherwise.
    #[tokio::test]
    async fn a_foreign_owner_is_retained() {
        let fixture = fixture(FakeCluster::default().with_object(config_map(
            "removed",
            Some("ferriscd-system/other:/ConfigMap:payments/removed"),
            None,
        )));
        let options = SyncOptions::default();

        let result = fixture
            .pruner(&options)
            .prune(&removed_key("removed"), None)
            .await
            .expect("prune");

        assert_eq!(
            result,
            PruneResult::Retained(RetainReason::ForeignOwner {
                owner: "ferriscd-system/other:/ConfigMap:payments/removed".to_owned()
            })
        );
        assert!(
            fixture.cluster.deletes().is_empty(),
            "another Application's object must never be deleted"
        );
    }

    #[tokio::test]
    async fn an_unmanaged_object_is_retained() {
        let fixture =
            fixture(FakeCluster::default().with_object(config_map("removed", None, None)));
        let options = SyncOptions::default();
        assert_eq!(
            fixture
                .pruner(&options)
                .prune(&removed_key("removed"), None)
                .await
                .expect("prune"),
            PruneResult::Retained(RetainReason::Unmanaged)
        );
        assert!(fixture.cluster.deletes().is_empty());
    }

    /// The opt-out annotation is re-read from the **fresh** object, not from the pass snapshot.
    #[tokio::test]
    async fn the_opt_out_annotation_is_honoured_on_the_re_read_object() {
        let fixture = fixture(FakeCluster::default().with_object(config_map(
            "removed",
            Some(&tracking_id("ConfigMap", "removed")),
            Some(json!({ annotations::PRUNE: "false" })),
        )));
        let options = SyncOptions::default();
        assert_eq!(
            fixture
                .pruner(&options)
                .prune(&removed_key("removed"), None)
                .await
                .expect("prune"),
            PruneResult::Retained(RetainReason::PruneOptedOut)
        );
        assert!(fixture.cluster.deletes().is_empty());
    }

    /// **Trap guard (H3):** the CRD orphan survives unless `pruneCRDs` is set.
    #[tokio::test]
    async fn crd_orphans_are_protected_by_default() {
        let key = ResourceKey::new(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.com",
        );
        let tracking = format!(
            "{OWNER_NAMESPACE}/{OWNER_NAME}:apiextensions.k8s.io/CustomResourceDefinition:/widgets.example.com"
        );
        let fixture =
            fixture(FakeCluster::default().with_object(crd("widgets.example.com", &tracking)));

        let options = SyncOptions::default();
        assert_eq!(
            fixture
                .pruner(&options)
                .prune(&key, Some("v1"))
                .await
                .expect("prune"),
            PruneResult::Retained(RetainReason::CrdPruneDisabled)
        );
        assert!(fixture.cluster.deletes().is_empty());

        let opted_in = SyncOptions {
            prune_crds: true,
            ..SyncOptions::default()
        };
        assert_eq!(
            fixture
                .pruner(&opted_in)
                .prune(&key, Some("v1"))
                .await
                .expect("prune"),
            PruneResult::Pruned
        );
        assert_eq!(
            fixture.cluster.deletes(),
            vec!["apiextensions.k8s.io/CustomResourceDefinition//widgets.example.com".to_owned()]
        );
    }

    /// **Trap guard (H3):** a `Namespace` orphan needs its own opt-in.
    #[tokio::test]
    async fn namespace_orphans_are_protected_by_default() {
        let key = ResourceKey::new("", "Namespace", None, "team-a");
        let tracking = format!("{OWNER_NAMESPACE}/{OWNER_NAME}:/Namespace:/team-a");
        let fixture =
            fixture(FakeCluster::default().with_object(namespace_object("team-a", &tracking)));

        let crds_only = SyncOptions {
            prune_crds: true,
            ..SyncOptions::default()
        };
        assert_eq!(
            fixture
                .pruner(&crds_only)
                .prune(&key, None)
                .await
                .expect("prune"),
            PruneResult::Retained(RetainReason::NamespacePruneDisabled),
            "pruneCRDs must never imply pruneNamespaces"
        );
        assert!(fixture.cluster.deletes().is_empty());
    }

    // ------------------------------------------------------------------
    // Failure handling: a failed delete stays tracked
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn a_failed_delete_is_an_error_so_the_orphan_is_retried() {
        let fixture = fixture(
            FakeCluster::default()
                .with_object(config_map(
                    "removed",
                    Some(&tracking_id("ConfigMap", "removed")),
                    None,
                ))
                .failing_delete("/ConfigMap/payments/removed", 500),
        );
        let options = SyncOptions::default();

        let err = fixture
            .pruner(&options)
            .prune(&removed_key("removed"), None)
            .await
            .expect_err("a failed delete must surface");
        assert_eq!(
            err.failure_class(),
            crate::FailureClass::Retryable,
            "a 500 retries on the next reconcile: {err}"
        );
        assert!(
            err.to_string().contains("/ConfigMap/payments/removed"),
            "the error must name the resource: {err}"
        );
    }

    #[tokio::test]
    async fn the_pruner_never_applies_anything() {
        // The `Applier` fake fails on apply, so any apply attempt would be an error, but the
        // stronger assertion is that a prune of an owned object only ever deletes.
        let fixture = fixture(FakeCluster::default().with_object(config_map(
            "removed",
            Some(&tracking_id("ConfigMap", "removed")),
            None,
        )));
        let options = SyncOptions::default();
        fixture
            .pruner(&options)
            .prune(&removed_key("removed"), None)
            .await
            .expect("prune");
        assert_eq!(fixture.cluster.deletes().len(), 1);
    }

    // ------------------------------------------------------------------
    // Pure helpers
    // ------------------------------------------------------------------

    #[test]
    fn prune_rails_only_look_at_the_given_object() {
        let options = SyncOptions::default();
        let configmap_key = removed_key("settings");
        let object = config_map("settings", None, None);
        assert_eq!(prune_rail(&configmap_key, &options, &object), None);

        let crd_key = ResourceKey::new(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.com",
        );
        assert_eq!(
            prune_rail(&crd_key, &options, &object),
            Some(RetainReason::CrdPruneDisabled)
        );

        let namespace_key = ResourceKey::new("", "Namespace", None, "team-a");
        assert_eq!(
            prune_rail(&namespace_key, &options, &object),
            Some(RetainReason::NamespacePruneDisabled)
        );

        let opted_out = config_map(
            "settings",
            None,
            Some(json!({ annotations::PRUNE: "FALSE" })),
        );
        assert_eq!(
            prune_rail(&configmap_key, &options, &opted_out),
            Some(RetainReason::PruneOptedOut)
        );
        // `"true"` is not an opt-out.
        let opted_in = config_map(
            "settings",
            None,
            Some(json!({ annotations::PRUNE: "true" })),
        );
        assert_eq!(prune_rail(&configmap_key, &options, &opted_in), None);
    }

    /// Cascade cleanup deletes in reverse apply order, so a namespace is removed last.
    #[test]
    fn prune_order_unwinds_a_cascade_in_reverse_apply_order() {
        let keys = vec![
            ResourceKey::new("", "Namespace", None, "team-a"),
            ResourceKey::new("", "ConfigMap", Some("team-a".to_owned()), "settings"),
            ResourceKey::new("apps", "Deployment", Some("team-a".to_owned()), "api"),
            ResourceKey::new("", "Service", Some("team-a".to_owned()), "api"),
        ];
        let ordered = sort_keys_prune_order(keys);
        let kinds: Vec<&str> = ordered.iter().map(|key| key.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec!["Deployment", "Service", "ConfigMap", "Namespace"]
        );
    }

    #[test]
    fn retain_reasons_render_actionably() {
        for (reason, needle) in [
            (
                RetainReason::ForeignOwner {
                    owner: "other/app".to_owned(),
                },
                "another Application",
            ),
            (RetainReason::CrdPruneDisabled, "pruneCRDs"),
            (RetainReason::NamespacePruneDisabled, "pruneNamespaces"),
            (RetainReason::Unmanaged, "tracking-id"),
        ] {
            assert!(reason.to_string().contains(needle), "{reason}");
            assert!(!reason.as_str().is_empty());
        }
        assert!(PruneResult::Pruned.is_pruned());
        assert!(!PruneResult::Retained(RetainReason::Deferred).is_pruned());
    }

    /// A dead-code check: the fake source must produce the `LiveStateError` type the pruner
    /// propagates, so the `?` in `prune` really is an error path (not an unreachable branch).
    #[test]
    fn live_state_errors_are_convertible() {
        let err: ReconcileError = LiveStateError::Api {
            resource: "/ConfigMap/payments/removed".to_owned(),
            code: 500,
            message: "boom".to_owned(),
        }
        .into();
        assert_eq!(err.failure_class(), crate::FailureClass::Retryable);
    }
}
