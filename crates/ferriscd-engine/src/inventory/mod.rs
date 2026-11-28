//! Crash-safe, version-agnostic GKNN inventory algebra.
//!
//! `status.inventory` is the durable record of every resource an `Application` owns. It
//! is what makes pruning possible at all: without it, a resource deleted from Git is
//! invisible to a `desired`-only fetcher (trap T1), and an object whose apply failed
//! would silently become a permanent orphan (finding C1).
//!
//! # Identity
//!
//! Identity is strictly **Group + Kind + Namespace + Name** ([`ResourceKey`]); the API
//! `version` is stored only as a non-key hint. Keeping `version` out of the key is what
//! stops an API/CRD upgrade (`v1beta1` -> `v1`) from turning a live object into an orphan
//! and self-pruning it (finding C2, ADR-003).
//!
//! # Formula
//!
//! ```text
//! to_fetch       = desired_keys ∪ prev_inventory_keys
//! orphans        = prev_inventory_keys \ desired_keys
//! next_inventory = (prev_inventory \ pruned_ok) ∪ applied_ok
//! ```
//!
//! The last line is the crash-safety property: only a **confirmed** prune removes an
//! entry and only a **confirmed** apply adds/refreshes one, so a partial apply or partial
//! prune failure never drops a live resource out of the inventory.
//!
//! Every function here is pure (no client, no I/O, no clock), so it is exhaustively
//! unit-testable and safe to call from any thread.

pub mod tracking;

use std::collections::{BTreeMap, BTreeSet};

use ferriscd_crd::status::InventoryEntry as StatusInventoryEntry;

use crate::manifest::types::{DesiredResource, ResourceKey};

pub use tracking::{
    APP_HASH_HEX_CHARS, Ownership, StampOptions, TrackingId, TrackingIdError, app_hash,
    classify_ownership, stamp_tracking_id, tracking_id_for,
};

/// One inventory entry's payload.
///
/// The resource identity is the [`Inventory`] map key, so this type deliberately carries
/// no key/name/namespace of its own — identity is never duplicated, and it is impossible
/// for the stored key string to drift from the map key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InventoryEntry {
    /// API version hint (`v1`, `v1beta1`, ...). Never part of the resource identity.
    ///
    /// [`inventory_from_desired`] stores the bare version (for example `v1` for
    /// `apps/v1`), because the group is already part of the key.
    pub version: String,
}

impl InventoryEntry {
    /// Builds an entry carrying only the version hint.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
        }
    }
}

/// Version-agnostic inventory keyed by GKNN identity, with the version kept as a hint.
///
/// `BTreeMap` gives deterministic ordering by [`ResourceKey`] (group, kind, namespace,
/// name) for free, so `/status` patches never churn on map iteration order.
pub type Inventory = BTreeMap<ResourceKey, InventoryEntry>;

/// A `status.inventory` key that is not canonical GKNN.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "malformed inventory key '{key}': expected `<group>/<kind>/<namespace>/<name>` \
     (four segments, no version)"
)]
pub struct InventoryKeyError {
    /// The offending key, exactly as read from `status.inventory`.
    pub key: String,
}

impl InventoryKeyError {
    /// Always `false`: reading back our own status is deterministic, so retrying can never
    /// repair a malformed key. Skipping it silently is not an option either — a dropped
    /// key becomes a permanent orphan, so callers must surface the error instead.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

/// Builds the inventory of a **desired** resource set.
///
/// The version hint is the bare [`GroupVersionKind::version`](crate::manifest::GroupVersionKind)
/// (`v1`, `v1beta1`, ...). An empty-string namespace is normalized to the cluster-scoped
/// `None`, so a key can never round-trip through `status.inventory` into a *different*
/// identity (which would fabricate an orphan). A duplicate GKNN key overwrites the
/// previous entry (last wins); upstream [`normalize`](crate::manifest::normalize) already
/// rejects duplicates, so this only affects defensive callers.
///
/// The mapping is faithful to whatever it is given: partitioning lifecycle hooks out of the
/// **permanent** inventory is the sync planner's job (Phase 10), matching
/// [`stamp_tracking_id`], which leaves hook resources unmarked.
#[must_use]
pub fn inventory_from_desired<'a>(
    desired: impl IntoIterator<Item = &'a DesiredResource>,
) -> Inventory {
    desired
        .into_iter()
        .map(|resource| {
            let mut key = resource.key.clone();
            if key.namespace.as_deref() == Some("") {
                key.namespace = None;
            }
            (key, InventoryEntry::new(resource.gvk.version.clone()))
        })
        .collect()
}

/// Keys to fetch live state for: `desired_keys ∪ prev_inventory_keys`.
///
/// The result is sorted by [`ResourceKey`] and de-duplicated, so the scoped live fetch is
/// deterministic (trap T1: a `desired`-only fetch makes pruning impossible).
#[must_use]
pub fn to_fetch(desired: &Inventory, prev_inventory: &Inventory) -> Vec<ResourceKey> {
    let mut keys: BTreeSet<ResourceKey> = BTreeSet::new();
    keys.extend(desired.keys().cloned());
    keys.extend(prev_inventory.keys().cloned());
    keys.into_iter().collect()
}

/// Orphans: `prev_inventory_keys \ desired_keys`, sorted by [`ResourceKey`].
///
/// Version upgrades never appear here because the key set is version-agnostic.
#[must_use]
pub fn orphans(desired: &Inventory, prev_inventory: &Inventory) -> Vec<ResourceKey> {
    prev_inventory
        .keys()
        .filter(|key| !desired.contains_key(*key))
        .cloned()
        .collect()
}

/// Crash-safe next inventory: `(prev_inventory \ pruned_ok) ∪ applied_ok`.
///
/// * `applied_ok` — resources whose SSA apply **confirmed** success, with their (possibly
///   upgraded) version hint. Their hints are refreshed in place; the keys never change.
/// * `pruned_ok` — resources whose delete **confirmed** success (`404 NotFound` counts).
///
/// Anything absent from both sets is preserved verbatim, which is the whole point: a
/// failed apply keeps the previous entry, and a failed prune keeps the orphan for the next
/// reconcile instead of leaking it forever.
///
/// Pruning is applied first and `applied_ok` second, so a key present in both (prune then
/// re-create within one operation) ends up tracked with the freshly applied hint.
#[must_use]
pub fn next_inventory(
    prev_inventory: &Inventory,
    applied_ok: &Inventory,
    pruned_ok: &[ResourceKey],
) -> Inventory {
    let mut next = prev_inventory.clone();
    for key in pruned_ok {
        next.remove(key);
    }
    for (key, entry) in applied_ok {
        next.insert(key.clone(), entry.clone());
    }
    next
}

/// Converts an inventory to the CRD `status.inventory` representation.
///
/// Entries are sorted by [`ResourceKey`] and the GKNN key is rendered exactly once
/// ([`ResourceKey::canonical`]); the version hint is attached as a non-key field.
#[must_use]
pub fn to_status_entries(inventory: &Inventory) -> Vec<StatusInventoryEntry> {
    inventory
        .iter()
        .map(|(key, entry)| StatusInventoryEntry::new(key.canonical(), entry.version.clone()))
        .collect()
}

/// Rebuilds an inventory from the CRD `status.inventory` representation.
///
/// Used on every reconcile to read `prev_inventory`, so it must never lose an entry:
/// silently skipping a malformed key would drop a live resource out of the inventory and
/// leak it forever. Duplicate keys collapse (last wins).
///
/// # Errors
///
/// Returns [`InventoryKeyError`] naming the first key that is not canonical
/// `<group>/<kind>/<namespace>/<name>` (for example a 5-segment key that accidentally
/// includes a version, or an empty kind/name).
pub fn from_status_entries<'a>(
    entries: impl IntoIterator<Item = &'a StatusInventoryEntry>,
) -> Result<Inventory, InventoryKeyError> {
    let mut inventory = Inventory::new();
    for entry in entries {
        let key = parse_gknn(&entry.key).ok_or_else(|| InventoryKeyError {
            key: entry.key.clone(),
        })?;
        inventory.insert(key, InventoryEntry::new(entry.version.clone()));
    }
    Ok(inventory)
}

/// Parses a canonical GKNN string `<group>/<kind>/<namespace>/<name>`.
///
/// The group may be empty (core group) and the namespace may be empty (cluster-scoped);
/// kind and name must be present and a version segment is rejected.
fn parse_gknn(canonical: &str) -> Option<ResourceKey> {
    let mut segments = canonical.split('/');
    let (Some(group), Some(kind), Some(namespace), Some(name), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return None;
    };

    if kind.is_empty() || name.is_empty() {
        return None;
    }

    Some(ResourceKey::new(
        group,
        kind,
        if namespace.is_empty() {
            None
        } else {
            Some(namespace.to_owned())
        },
        name,
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::manifest::types::GroupVersionKind;

    fn key(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> ResourceKey {
        ResourceKey::new(group, kind, namespace.map(str::to_owned), name)
    }

    fn desired_resource(
        group: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
        version: &str,
    ) -> DesiredResource {
        let api_version = if group.is_empty() {
            version.to_owned()
        } else {
            format!("{group}/{version}")
        };
        let object = serde_json::from_value(json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": { "name": name, "namespace": namespace },
        }))
        .expect("valid DynamicObject");

        DesiredResource {
            key: key(group, kind, namespace, name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("valid apiVersion"),
            object,
            source_file: "fixture.yaml".to_owned(),
        }
    }

    /// A representative key pool: core/grouped, namespaced/cluster-scoped.
    fn pool() -> Vec<ResourceKey> {
        vec![
            key("", "Namespace", None, "team-a"),
            key("", "Service", Some("payments"), "api"),
            key("", "ConfigMap", Some("payments"), "settings"),
            key("", "ConfigMap", Some("billing"), "settings"),
            key("", "Secret", Some("payments"), "creds"),
            key("apps", "Deployment", Some("payments"), "api"),
            key("apps", "Deployment", Some("billing"), "worker"),
            key("apps", "StatefulSet", Some("payments"), "db"),
            key("rbac.authorization.k8s.io", "ClusterRole", None, "admin"),
            key(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                "widgets",
            ),
            key("networking.k8s.io", "Ingress", Some("payments"), "web"),
            key("example.com", "Widget", Some("payments"), "one"),
        ]
    }

    fn inventory_of_keys(keys: &[ResourceKey], version: &str) -> Inventory {
        keys.iter()
            .map(|key| (key.clone(), InventoryEntry::new(version)))
            .collect()
    }

    fn keys_of(inventory: &Inventory) -> Vec<ResourceKey> {
        inventory.keys().cloned().collect()
    }

    #[test]
    fn to_fetch_is_the_sorted_union_of_desired_and_previous_keys() {
        let desired = inventory_of_keys(
            &[
                key("apps", "Deployment", Some("payments"), "api"),
                key("", "ConfigMap", Some("payments"), "settings"),
            ],
            "v1",
        );
        let prev = inventory_of_keys(
            &[
                key("", "ConfigMap", Some("payments"), "settings"),
                key("", "Service", Some("payments"), "api"),
            ],
            "v1",
        );

        let fetch = to_fetch(&desired, &prev);
        assert_eq!(
            fetch,
            vec![
                key("", "ConfigMap", Some("payments"), "settings"),
                key("", "Service", Some("payments"), "api"),
                key("apps", "Deployment", Some("payments"), "api"),
            ],
            "union must be de-duplicated and sorted by ResourceKey"
        );

        // A previously managed resource that is no longer desired must still be fetched
        // (otherwise a Git deletion is invisible and can never be pruned).
        let deleted = key("", "Service", Some("payments"), "api");
        assert!(fetch.contains(&deleted));
    }

    #[test]
    fn orphans_are_previous_keys_absent_from_desired() {
        let desired =
            inventory_of_keys(&[key("apps", "Deployment", Some("payments"), "api")], "v1");
        let prev = inventory_of_keys(
            &[
                key("apps", "Deployment", Some("payments"), "api"),
                key("", "Service", Some("payments"), "api"),
                key("", "ConfigMap", Some("billing"), "settings"),
            ],
            "v1",
        );

        assert_eq!(
            orphans(&desired, &prev),
            vec![
                key("", "ConfigMap", Some("billing"), "settings"),
                key("", "Service", Some("payments"), "api"),
            ]
        );
    }

    #[test]
    fn failed_apply_of_an_existing_resource_preserves_it() {
        let existing = key("apps", "Deployment", Some("payments"), "api");
        let failing = key("", "Service", Some("payments"), "api");
        let prev = inventory_of_keys(&[existing.clone(), failing.clone()], "v1beta1");
        let desired = inventory_from_desired([&desired_resource(
            "apps",
            "Deployment",
            Some("payments"),
            "api",
            "v1",
        )]);

        // Only the Deployment applied; the Service SSA apply failed, so it is not in
        // `applied_ok` — but it is still in `prev_inventory` and must survive.
        let next = next_inventory(&prev, &desired, &[]);

        assert_eq!(
            next.get(&failing),
            Some(&InventoryEntry::new("v1beta1")),
            "a failed apply must not drop the resource or rewrite its version hint"
        );
        assert_eq!(next.get(&existing), Some(&InventoryEntry::new("v1")));
        assert_eq!(
            orphans(&desired, &next),
            vec![failing],
            "the surviving entry is still (and correctly) an orphan"
        );
        assert_eq!(
            next.len(),
            2,
            "no live resource may leak out of the inventory"
        );
    }

    #[test]
    fn failed_prune_of_an_orphan_preserves_it() {
        let kept = key("apps", "Deployment", Some("payments"), "api");
        let orphan = key("", "Service", Some("payments"), "api");
        let prev = inventory_of_keys(&[kept.clone(), orphan.clone()], "v1");
        let desired = inventory_of_keys(std::slice::from_ref(&kept), "v1");

        // The orphan's delete failed, so the controller confirms nothing pruned.
        let next = next_inventory(&prev, &desired, &[]);
        assert_eq!(
            next.get(&orphan),
            Some(&InventoryEntry::new("v1")),
            "a failed prune must keep the orphan tracked"
        );
        assert_eq!(
            orphans(&desired, &next),
            vec![orphan.clone()],
            "the orphan must be retried on the next reconcile"
        );

        // Once the delete confirms, the orphan leaves the inventory for good.
        let pruned = next_inventory(&prev, &desired, std::slice::from_ref(&orphan));
        assert!(!pruned.contains_key(&orphan));
        assert_eq!(keys_of(&pruned), vec![kept]);
    }

    #[test]
    fn version_upgrade_updates_the_hint_with_zero_orphans() {
        let upgraded = key("networking.k8s.io", "Ingress", Some("payments"), "web");

        let prev = inventory_of_keys(std::slice::from_ref(&upgraded), "v1beta1");
        let upgraded_ingress = desired_resource(
            "networking.k8s.io",
            "Ingress",
            Some("payments"),
            "web",
            "v1",
        );
        let desired = inventory_from_desired([&upgraded_ingress]);

        assert_eq!(
            orphans(&desired, &prev),
            Vec::<ResourceKey>::new(),
            "an apiVersion upgrade must never produce an orphan (finding C2)"
        );
        assert_eq!(to_fetch(&desired, &prev), vec![upgraded.clone()]);

        let next = next_inventory(&prev, &desired, &[]);
        assert_eq!(next.len(), 1);
        assert_eq!(
            next.get(&upgraded),
            Some(&InventoryEntry::new("v1")),
            "the applied entry refreshes the version hint without changing identity"
        );

        // The serialized identity is byte-identical before and after the upgrade.
        let before: Vec<String> = to_status_entries(&prev)
            .iter()
            .map(|entry| entry.key.clone())
            .collect();
        let after: Vec<String> = to_status_entries(&next)
            .iter()
            .map(|entry| entry.key.clone())
            .collect();
        assert_eq!(before, after);

        // A repeat reconcile at the new version stays stable (no churn, no orphans).
        assert_eq!(orphans(&desired, &next), Vec::<ResourceKey>::new());
        assert_eq!(next_inventory(&next, &desired, &[]), next);
    }

    #[test]
    fn status_entries_are_deterministic_and_sorted_by_resource_key() {
        let shuffled = vec![
            desired_resource("apps", "Deployment", Some("payments"), "api", "v1"),
            desired_resource("", "Namespace", None, "team-a", "v1"),
            desired_resource("", "Service", Some("payments"), "api", "v1"),
            desired_resource(
                "rbac.authorization.k8s.io",
                "ClusterRole",
                None,
                "admin",
                "v1",
            ),
            desired_resource("", "ConfigMap", Some("billing"), "settings", "v1"),
        ];
        let inventory = inventory_from_desired(shuffled.iter());

        let first = to_status_entries(&inventory);
        let second = to_status_entries(&inventory_from_desired(shuffled.iter()));
        assert_eq!(first, second, "serialization must be byte-stable");

        let keys: Vec<&str> = first.iter().map(|entry| entry.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                // Empty (core) group sorts first, then "" namespace before "billing" etc.
                "/ConfigMap/billing/settings",
                "/Namespace//team-a",
                "/Service/payments/api",
                "apps/Deployment/payments/api",
                "rbac.authorization.k8s.io/ClusterRole//admin",
            ]
        );
        for entry in &first {
            assert!(
                !entry.key.contains("v1"),
                "inventory keys must never contain a version: {}",
                entry.key
            );
        }

        // Rebuilding from the same desired set (different iteration order) is identical.
        let mut reversed = shuffled.clone();
        reversed.reverse();
        assert_eq!(
            first,
            to_status_entries(&inventory_from_desired(reversed.iter()))
        );
    }

    #[test]
    fn duplicate_keys_collapse_and_empty_namespaces_normalize() {
        // Duplicate GKNN: last entry wins, the map keeps a single identity.
        let duplicates = [
            desired_resource("apps", "Deployment", Some("payments"), "api", "v1beta1"),
            desired_resource("apps", "Deployment", Some("payments"), "api", "v1"),
        ];
        let inventory = inventory_from_desired(duplicates.iter());
        assert_eq!(inventory.len(), 1, "duplicate GKNN keys must collapse");
        assert_eq!(
            inventory
                .get(&key("apps", "Deployment", Some("payments"), "api"))
                .map(|entry| entry.version.as_str()),
            Some("v1"),
            "the last write wins"
        );

        // `Some("")` is not a distinct identity from cluster-scoped `None`.
        let mut empty_namespace = desired_resource("", "Namespace", None, "team-a", "v1");
        empty_namespace.key.namespace = Some(String::new());
        let inventory = inventory_from_desired([&empty_namespace]);
        assert_eq!(
            keys_of(&inventory),
            vec![key("", "Namespace", None, "team-a")],
            "an empty namespace must normalize to cluster-scoped"
        );

        // ... and it round-trips, so it can never fabricate an orphan.
        let entries = to_status_entries(&inventory);
        assert_eq!(entries[0].key, "/Namespace//team-a");
        assert_eq!(
            from_status_entries(&entries).expect("round-trip"),
            inventory,
            "normalized identity must round-trip through status"
        );
    }

    #[test]
    fn empty_inputs_produce_empty_outputs() {
        let empty = Inventory::new();
        assert!(to_fetch(&empty, &empty).is_empty());
        assert!(orphans(&empty, &empty).is_empty());
        assert!(next_inventory(&empty, &empty, &[]).is_empty());
        assert!(to_status_entries(&empty).is_empty());
        assert_eq!(
            from_status_entries(&[] as &[StatusInventoryEntry]).expect("empty status"),
            empty
        );

        let prev = inventory_of_keys(
            &[
                key("apps", "Deployment", Some("payments"), "api"),
                key("", "Service", Some("payments"), "api"),
            ],
            "v1",
        );

        // Nothing desired: every previous key is an orphan, nothing is lost.
        assert_eq!(to_fetch(&empty, &prev), keys_of(&prev));
        assert_eq!(orphans(&empty, &prev), keys_of(&prev));
        assert_eq!(next_inventory(&prev, &empty, &[]), prev);

        // Nothing previous: the desired set is fetched, applied and tracked.
        assert_eq!(to_fetch(&prev, &empty), keys_of(&prev));
        assert!(orphans(&prev, &empty).is_empty());
        assert_eq!(next_inventory(&empty, &prev, &[]), prev);
    }

    #[test]
    fn prune_removes_and_apply_refreshes_on_overlap() {
        let existing = key("apps", "Deployment", Some("payments"), "api");
        let orphan = key("", "Service", Some("payments"), "api");
        let prev = inventory_of_keys(&[existing.clone(), orphan.clone()], "v1");

        // Pruning is applied before applying, so a key in both sets survives with the
        // freshly applied hint.
        let applied = inventory_of_keys(std::slice::from_ref(&existing), "v2");
        let next = next_inventory(&prev, &applied, &[existing.clone(), orphan.clone()]);
        assert_eq!(
            next,
            inventory_of_keys(std::slice::from_ref(&existing), "v2"),
            "prune then re-apply must keep the re-applied entry"
        );

        // Pruning a key that is not tracked is a no-op.
        let unknown = key("", "ConfigMap", Some("payments"), "unknown");
        assert_eq!(next_inventory(&prev, &Inventory::new(), &[unknown]), prev);
    }

    #[test]
    fn status_entries_round_trip_and_reject_malformed_keys() {
        let inventory = inventory_of_keys(&pool(), "v1");
        let entries = to_status_entries(&inventory);
        assert_eq!(entries.len(), pool().len());
        assert_eq!(
            from_status_entries(&entries).expect("round-trip"),
            inventory,
            "every GKNN identity must survive a status round-trip"
        );

        for bad in [
            "apps/v1/Deployment/payments/api",
            "Deployment/payments/api",
            "apps//payments/api",
            "apps/Deployment//",
            "",
            "apps/Deployment/payments",
        ] {
            let malformed = [StatusInventoryEntry::new(bad, "v1")];
            let err = from_status_entries(&malformed).expect_err("must reject malformed key");
            assert_eq!(err.key, bad, "the error must name the offending key");
            assert!(!err.is_retryable());
            assert!(
                err.to_string().contains(&format!("'{bad}'")),
                "Display must quote the offending key: {err}"
            );
        }
    }

    /// Deterministic pseudo-random subset selection (no external RNG dependency).
    fn next_bit(state: &mut u64) -> bool {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (*state >> 63) & 1 == 1
    }

    fn random_inventory(pool: &[ResourceKey], state: &mut u64) -> Inventory {
        let mut inventory = Inventory::new();
        for key in pool {
            if next_bit(state) {
                let version = if next_bit(state) { "v1" } else { "v1beta1" };
                inventory.insert(key.clone(), InventoryEntry::new(version));
            }
        }
        inventory
    }

    fn random_keys(pool: &[ResourceKey], state: &mut u64) -> Vec<ResourceKey> {
        pool.iter().filter(|_| next_bit(state)).cloned().collect()
    }

    #[test]
    fn set_algebra_properties_hold_for_pseudo_random_subsets() {
        let pool = pool();
        let mut state = 0x2545_f491_4f6c_dd1d_u64;

        for _ in 0..512 {
            let prev = random_inventory(&pool, &mut state);
            let desired = random_inventory(&pool, &mut state);
            let applied = random_inventory(&pool, &mut state);
            let pruned = random_keys(&pool, &mut state);

            // to_fetch = desired ∪ prev, sorted and de-duplicated.
            let expected_fetch: BTreeSet<ResourceKey> = desired
                .keys()
                .chain(prev.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            let fetch = to_fetch(&desired, &prev);
            assert_eq!(
                fetch.iter().cloned().collect::<BTreeSet<_>>(),
                expected_fetch
            );
            assert!(
                fetch.windows(2).all(|pair| pair[0] < pair[1]),
                "to_fetch must be sorted and de-duplicated"
            );

            // orphans = prev \ desired.
            assert_eq!(
                orphans(&desired, &prev)
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                prev.keys()
                    .filter(|key| !desired.contains_key(*key))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            );

            // next_inventory = (prev \ pruned) ∪ applied, and nothing leaks.
            let next = next_inventory(&prev, &applied, &pruned);
            let pruned_set: BTreeSet<ResourceKey> = pruned.iter().cloned().collect();

            for (key, entry) in &prev {
                if !pruned_set.contains(key) && !applied.contains_key(key) {
                    assert_eq!(
                        next.get(key),
                        Some(entry),
                        "an unpruned, re-applied key must keep its previous entry verbatim"
                    );
                }
            }
            for (key, entry) in &applied {
                assert_eq!(
                    next.get(key),
                    Some(entry),
                    "every confirmed apply must be tracked with its fresh hint"
                );
            }
            let expected_next: BTreeSet<ResourceKey> = prev
                .keys()
                .filter(|key| !pruned_set.contains(*key))
                .chain(applied.keys())
                .cloned()
                .collect();
            assert_eq!(
                next.keys().cloned().collect::<BTreeSet<_>>(),
                expected_next,
                "the inventory may only contain (unpruned previous ∪ applied) keys"
            );

            // Determinism: the same inputs always produce the same inventory.
            assert_eq!(next_inventory(&prev, &applied, &pruned), next);
        }
    }
}
