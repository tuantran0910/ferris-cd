//! Deterministic Kubernetes priority-tier ordering (T08.1).
//!
//! Applying a bundle in filesystem order is broken in both directions:
//!
//! * a `Deployment` applied before its `Namespace` fails with `404`,
//! * a custom resource applied before its `CustomResourceDefinition` fails with
//!   `NoMatchesForKind` (trap T6), and
//! * pruning in apply order deletes a `Namespace` before the workloads inside it, which makes
//!   the delete cascade look like a partial failure.
//!
//! This module therefore defines **one** total order ([`TIERS`]) and derives the prune order
//! from it as the *exact reverse*: everything that had to exist first is removed last.
//!
//! # The twelve tiers
//!
//! | Tier | Kinds | Why |
//! |---|---|---|
//! | 0 | `Namespace` | nothing can be created inside a namespace that does not exist |
//! | 1 | `ResourceQuota`, `LimitRange` | a quota that arrives after its workloads rejects them |
//! | 2 | `CustomResourceDefinition` | every custom kind below depends on it |
//! | 3 | `ServiceAccount` | pods and RBAC bindings reference it |
//! | 4 | `Role`, `ClusterRole` | a binding to a missing role grants nothing |
//! | 5 | `RoleBinding`, `ClusterRoleBinding` | |
//! | 6 | `ConfigMap`, `Secret` | mounted/consumed by workloads and storage |
//! | 7 | `StorageClass`, `PersistentVolumeClaim` | a pod cannot schedule on a pending PVC |
//! | 8 | `Service` | endpoints before the workload, so its first apply is valid |
//! | 9 | `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob` | workloads |
//! | 10 | `Ingress`, `NetworkPolicy`, `HorizontalPodAutoscaler`, `PodDisruptionBudget` | attach to a workload/service |
//! | 11 | everything else (custom resources, webhooks, …) | depends on a CRD applied in tier 2 |
//!
//! # Trap guard: custom resources never outrank a CRD
//!
//! Tier lookup matches on **group + kind**, never on `kind` alone. A custom resource may legally
//! be called `Service`, `Deployment`, or even `CustomResourceDefinition` in its own API group; a
//! kind-only match would sort it into a native tier and let it be applied before the CRD that
//! defines it. Anything not in the table above is tier [`TIER_CUSTOM_RESOURCE`], which is the
//! highest tier, so a custom resource can never precede the CRD that establishes its kind.
//!
//! # Determinism
//!
//! Within a tier the tie-break is the version-agnostic [`ResourceKey`] (group, kind, namespace,
//! name), so two processes sorting the same bundle produce byte-identical orders and a reconcile
//! never reorders itself. [`sort_prune_order`] is `sort_apply_order` reversed, element for
//! element — not a second, independently maintained ordering that could drift.

use crate::manifest::types::{DesiredResource, ResourceKey};

/// API group serving `CustomResourceDefinition`.
pub const APIEXTENSIONS_GROUP: &str = "apiextensions.k8s.io";

/// Kind of the `CustomResourceDefinition` object itself.
pub const CRD_KIND: &str = "CustomResourceDefinition";

/// Tier 0: `Namespace`.
pub const TIER_NAMESPACE: u8 = 0;
/// Tier 1: `ResourceQuota`, `LimitRange`.
pub const TIER_QUOTA: u8 = 1;
/// Tier 2: `CustomResourceDefinition`.
pub const TIER_CRD: u8 = 2;
/// Tier 3: `ServiceAccount`.
pub const TIER_SERVICE_ACCOUNT: u8 = 3;
/// Tier 4: `Role`, `ClusterRole`.
pub const TIER_RBAC_ROLE: u8 = 4;
/// Tier 5: `RoleBinding`, `ClusterRoleBinding`.
pub const TIER_RBAC_BINDING: u8 = 5;
/// Tier 6: `ConfigMap`, `Secret`.
pub const TIER_CONFIG: u8 = 6;
/// Tier 7: `StorageClass`, `PersistentVolumeClaim`.
pub const TIER_STORAGE: u8 = 7;
/// Tier 8: `Service`.
pub const TIER_SERVICE: u8 = 8;
/// Tier 9: `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`.
pub const TIER_WORKLOAD: u8 = 9;
/// Tier 10: `Ingress`, `NetworkPolicy`, `HorizontalPodAutoscaler`, `PodDisruptionBudget`.
///
/// Named "edge" because it is the tier of everything that exposes, shapes or scales a workload
/// (routing, admission-ish policy, autoscaling) rather than a single kind.
pub const TIER_EDGE: u8 = 10;
/// Tier 11: custom resources, webhooks, and every kind without a native rule.
pub const TIER_CUSTOM_RESOURCE: u8 = 11;

/// The highest tier, i.e. the tier custom resources are applied in.
///
/// Exposed so the sync planner can assert that a prune order really is the reverse of an apply
/// order without hard-coding the number.
pub const MAX_TIER: u8 = TIER_CUSTOM_RESOURCE;

/// Every tier, lowest (apply first) to highest.
pub const TIERS: [u8; 12] = [
    TIER_NAMESPACE,
    TIER_QUOTA,
    TIER_CRD,
    TIER_SERVICE_ACCOUNT,
    TIER_RBAC_ROLE,
    TIER_RBAC_BINDING,
    TIER_CONFIG,
    TIER_STORAGE,
    TIER_SERVICE,
    TIER_WORKLOAD,
    TIER_EDGE,
    TIER_CUSTOM_RESOURCE,
];

/// Returns the deterministic apply tier of `resource`.
#[must_use]
pub fn tier(resource: &DesiredResource) -> u8 {
    key_tier(&resource.key)
}

/// Returns the deterministic apply tier of a `group`/`kind` pair.
///
/// Tier matching is **group-aware** on purpose: a custom resource is free to be called
/// `Service` or `Deployment` in its own API group, and matching on `kind` alone would sort it
/// into a native tier — i.e. before the `CustomResourceDefinition` that defines it (trap T6).
#[must_use]
pub fn tier_of(group: &str, kind: &str) -> u8 {
    match (group, kind) {
        ("", "Namespace") => TIER_NAMESPACE,
        ("", "ResourceQuota" | "LimitRange") => TIER_QUOTA,
        (APIEXTENSIONS_GROUP, CRD_KIND) => TIER_CRD,
        ("", "ServiceAccount") => TIER_SERVICE_ACCOUNT,
        ("rbac.authorization.k8s.io", "Role" | "ClusterRole") => TIER_RBAC_ROLE,
        ("rbac.authorization.k8s.io", "RoleBinding" | "ClusterRoleBinding") => TIER_RBAC_BINDING,
        ("", "ConfigMap" | "Secret") => TIER_CONFIG,
        ("storage.k8s.io", "StorageClass") | ("", "PersistentVolumeClaim") => TIER_STORAGE,
        ("", "Service") => TIER_SERVICE,
        ("apps", "Deployment" | "StatefulSet" | "DaemonSet") | ("batch", "Job" | "CronJob") => {
            TIER_WORKLOAD
        }
        ("networking.k8s.io", "Ingress" | "NetworkPolicy")
        | ("autoscaling", "HorizontalPodAutoscaler")
        | ("policy", "PodDisruptionBudget") => TIER_EDGE,
        // Custom resources, admission webhooks, and anything else: last.
        _ => TIER_CUSTOM_RESOURCE,
    }
}

/// Returns the deterministic apply tier of `key`.
#[must_use]
pub fn key_tier(key: &ResourceKey) -> u8 {
    tier_of(&key.group, &key.kind)
}

/// Returns whether `key` identifies a `CustomResourceDefinition`.
#[must_use]
pub fn is_crd_key(key: &ResourceKey) -> bool {
    key.group == APIEXTENSIONS_GROUP && key.kind == CRD_KIND
}

/// Returns whether `key` identifies a core `Namespace`.
#[must_use]
pub fn is_namespace_key(key: &ResourceKey) -> bool {
    key.group.is_empty() && key.kind == "Namespace"
}

/// The total apply order over `(tier, ResourceKey)`.
///
/// Exposed so callers that only have *references* to resources (the sync planner sorts a
/// borrowed slice) can use the one comparator instead of re-deriving it.
#[must_use]
pub fn apply_cmp(left: &ResourceKey, right: &ResourceKey) -> std::cmp::Ordering {
    key_tier(left)
        .cmp(&key_tier(right))
        .then_with(|| left.cmp(right))
}

/// Sorts `resources` into apply order (tier ascending, then [`ResourceKey`] ascending).
#[must_use]
pub fn sort_apply_order(mut resources: Vec<DesiredResource>) -> Vec<DesiredResource> {
    resources.sort_by(|left, right| apply_cmp(&left.key, &right.key));
    resources
}

/// Sorts `resources` into prune order: the **exact reverse** of [`sort_apply_order`].
///
/// Implemented as "sort into apply order, then reverse" rather than as a second comparator, so
/// the two orders can never drift: whatever was applied first is pruned last, and the
/// intra-tier tie-break is reversed too (deterministic, not merely "reversed tiers").
#[must_use]
pub fn sort_prune_order(resources: Vec<DesiredResource>) -> Vec<DesiredResource> {
    let mut pruned = sort_apply_order(resources);
    pruned.reverse();
    pruned
}

/// Sorts bare [`ResourceKey`]s into apply order (tier ascending, then key ascending).
#[must_use]
pub fn sort_keys_apply_order(mut keys: Vec<ResourceKey>) -> Vec<ResourceKey> {
    keys.sort_by(apply_cmp);
    keys
}

/// Sorts bare [`ResourceKey`]s into prune order: the exact reverse of
/// [`sort_keys_apply_order`].
///
/// Orphans are only known by their GKNN key (`status.inventory` stores nothing else), and the
/// pruner must still unwind them in reverse apply order.
#[must_use]
pub fn sort_keys_prune_order(keys: Vec<ResourceKey>) -> Vec<ResourceKey> {
    let mut pruned = sort_keys_apply_order(keys);
    pruned.reverse();
    pruned
}

/// Backwards-compatible alias of [`sort_apply_order`].
///
/// `v0.1`–`v0.2` called this "sort by tier"; the contract (deterministic, kind-priority first)
/// is unchanged, the name now says *which* order it is.
#[must_use]
pub fn sort_by_tier(resources: Vec<DesiredResource>) -> Vec<DesiredResource> {
    sort_apply_order(resources)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::manifest::types::GroupVersionKind;

    fn resource(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> DesiredResource {
        let api_version = if group.is_empty() {
            "v1".to_owned()
        } else {
            format!("{group}/v1")
        };
        let object = serde_json::from_value(json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": { "name": name, "namespace": namespace },
        }))
        .expect("valid DynamicObject");

        DesiredResource {
            key: ResourceKey::new(group, kind, namespace.map(str::to_owned), name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("parse gvk"),
            object,
            source_file: "fixture.yaml".to_owned(),
        }
    }

    fn key(resource: &DesiredResource) -> String {
        resource.key.canonical()
    }

    fn keys(resources: &[DesiredResource]) -> Vec<String> {
        resources.iter().map(key).collect()
    }

    /// One representative of every tier, in apply order.
    fn one_per_tier() -> Vec<DesiredResource> {
        vec![
            resource("", "Namespace", None, "team-a"),
            resource("", "ResourceQuota", Some("team-a"), "quota"),
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                "widgets.example.com",
            ),
            resource("", "ServiceAccount", Some("team-a"), "runner"),
            resource("rbac.authorization.k8s.io", "ClusterRole", None, "reader"),
            resource(
                "rbac.authorization.k8s.io",
                "RoleBinding",
                Some("team-a"),
                "reader",
            ),
            resource("", "ConfigMap", Some("team-a"), "settings"),
            resource("", "PersistentVolumeClaim", Some("team-a"), "data"),
            resource("", "Service", Some("team-a"), "api"),
            resource("apps", "Deployment", Some("team-a"), "api"),
            resource("networking.k8s.io", "Ingress", Some("team-a"), "web"),
            resource("example.com", "Widget", Some("team-a"), "one"),
        ]
    }

    #[test]
    fn tier_assignment_covers_every_documented_tier() {
        let cases: [(&str, &str, u8); 22] = [
            // Tier 0
            ("", "Namespace", TIER_NAMESPACE),
            // Tier 1
            ("", "ResourceQuota", TIER_QUOTA),
            ("", "LimitRange", TIER_QUOTA),
            // Tier 2
            (APIEXTENSIONS_GROUP, CRD_KIND, TIER_CRD),
            // Tier 3
            ("", "ServiceAccount", TIER_SERVICE_ACCOUNT),
            // Tier 4
            ("rbac.authorization.k8s.io", "ClusterRole", TIER_RBAC_ROLE),
            ("rbac.authorization.k8s.io", "Role", TIER_RBAC_ROLE),
            // Tier 5
            (
                "rbac.authorization.k8s.io",
                "ClusterRoleBinding",
                TIER_RBAC_BINDING,
            ),
            (
                "rbac.authorization.k8s.io",
                "RoleBinding",
                TIER_RBAC_BINDING,
            ),
            // Tier 6
            ("", "ConfigMap", TIER_CONFIG),
            ("", "Secret", TIER_CONFIG),
            // Tier 7
            ("storage.k8s.io", "StorageClass", TIER_STORAGE),
            ("", "PersistentVolumeClaim", TIER_STORAGE),
            // Tier 8
            ("", "Service", TIER_SERVICE),
            // Tier 9
            ("apps", "Deployment", TIER_WORKLOAD),
            ("apps", "StatefulSet", TIER_WORKLOAD),
            ("apps", "DaemonSet", TIER_WORKLOAD),
            ("batch", "Job", TIER_WORKLOAD),
            ("batch", "CronJob", TIER_WORKLOAD),
            // Tier 10
            ("networking.k8s.io", "Ingress", TIER_EDGE),
            ("networking.k8s.io", "NetworkPolicy", TIER_EDGE),
            ("policy", "PodDisruptionBudget", TIER_EDGE),
        ];
        for (group, kind, expected) in cases {
            assert_eq!(tier_of(group, kind), expected, "{group}/{kind}");
        }
        assert_eq!(tier_of("autoscaling", "HorizontalPodAutoscaler"), TIER_EDGE);

        // Tier 11: custom resources, webhooks, and anything unrecognized.
        for (group, kind) in [
            ("example.com", "Widget"),
            (
                "admissionregistration.k8s.io",
                "ValidatingWebhookConfiguration",
            ),
            (
                "admissionregistration.k8s.io",
                "MutatingWebhookConfiguration",
            ),
            ("", "Pod"),
            ("apps", "ReplicaSet"),
        ] {
            assert_eq!(tier_of(group, kind), TIER_CUSTOM_RESOURCE, "{group}/{kind}");
        }
        assert_eq!(MAX_TIER, TIER_CUSTOM_RESOURCE);

        // The documented tier list is exactly the twelve tiers, strictly ascending.
        assert_eq!(TIERS.len(), 12);
        assert!(TIERS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn every_tier_constant_is_used_by_at_least_one_kind() {
        let covered: BTreeSet<u8> = [
            ("", "Namespace"),
            ("", "ResourceQuota"),
            (APIEXTENSIONS_GROUP, CRD_KIND),
            ("", "ServiceAccount"),
            ("rbac.authorization.k8s.io", "Role"),
            ("rbac.authorization.k8s.io", "RoleBinding"),
            ("", "Secret"),
            ("", "PersistentVolumeClaim"),
            ("", "Service"),
            ("apps", "Deployment"),
            ("networking.k8s.io", "Ingress"),
            ("example.com", "Widget"),
        ]
        .into_iter()
        .map(|(group, kind)| tier_of(group, kind))
        .collect();
        assert_eq!(
            covered,
            TIERS.into_iter().collect::<BTreeSet<_>>(),
            "every declared tier must be reachable"
        );
    }

    /// **Trap guard (T6):** whatever a bundle contains, every
    /// `CustomResourceDefinition` is applied before every custom resource.
    #[test]
    fn custom_resources_always_sort_after_every_crd() {
        // `example.com/Service` and `example.com/Deployment` collide with native kind names on
        // purpose: a kind-only tier match would sort them into tiers 8 and 9.
        let resources = vec![
            resource("example.com", "Service", Some("team-a"), "shadow"),
            resource("example.com", "Deployment", Some("team-a"), "shadow"),
            resource(
                "example.com",
                "CustomResourceDefinition",
                Some("team-a"),
                "shadow",
            ),
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                "widgets.example.com",
            ),
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                None,
                "gadgets.example.com",
            ),
            resource("", "Service", Some("team-a"), "api"),
            resource("", "Namespace", None, "team-a"),
        ];

        let sorted = sort_apply_order(resources);
        let first_custom = sorted
            .iter()
            .position(|resource| resource.key.group == "example.com")
            .expect("custom resources present");
        let last_crd = sorted
            .iter()
            .rposition(|resource| is_crd_key(&resource.key))
            .expect("CRDs present");
        assert!(
            last_crd < first_custom,
            "every CRD must precede every custom resource: {:?}",
            keys(&sorted)
        );
        for resource in &sorted[first_custom..] {
            assert_eq!(tier(resource), TIER_CUSTOM_RESOURCE, "{resource:?}");
        }

        // The CRDs themselves follow the namespace (they are cluster-scoped infrastructure).
        assert_eq!(sorted[0].key.name, "team-a");
        assert!(is_namespace_key(&sorted[0].key));
    }

    #[test]
    fn apply_order_is_tier_ascending_then_key_ascending() {
        let sorted = sort_apply_order(one_per_tier());
        let tiers: Vec<u8> = sorted.iter().map(tier).collect();
        assert_eq!(tiers, TIERS.to_vec(), "{:?}", keys(&sorted));

        // Intra-tier tie-break: ResourceKey ascending (group, kind, namespace, name).
        let unordered = vec![
            resource("", "ConfigMap", Some("team-b"), "settings"),
            resource("", "ConfigMap", Some("team-a"), "zeta"),
            resource("", "ConfigMap", Some("team-a"), "alpha"),
            resource("", "Secret", Some("team-a"), "creds"),
        ];
        assert_eq!(
            keys(&sort_apply_order(unordered.clone())),
            vec![
                "/ConfigMap/team-a/alpha".to_owned(),
                "/ConfigMap/team-a/zeta".to_owned(),
                "/ConfigMap/team-b/settings".to_owned(),
                "/Secret/team-a/creds".to_owned(),
            ]
        );
        // ... and the reverse tie-break for pruning.
        assert_eq!(
            keys(&sort_prune_order(unordered)),
            vec![
                "/Secret/team-a/creds".to_owned(),
                "/ConfigMap/team-b/settings".to_owned(),
                "/ConfigMap/team-a/zeta".to_owned(),
                "/ConfigMap/team-a/alpha".to_owned(),
            ]
        );
    }

    /// **Verification:** prune order is the *exact* reverse of apply order, element for element.
    #[test]
    fn prune_order_is_the_exact_reverse_of_apply_order() {
        let resources = one_per_tier();
        let apply = sort_apply_order(resources.clone());
        let prune = sort_prune_order(resources.clone());
        assert_eq!(apply.len(), prune.len());

        let reversed: Vec<String> = apply.iter().rev().map(key).collect();
        assert_eq!(
            keys(&prune),
            reversed,
            "prune order must be apply order reversed"
        );
        assert_eq!(keys(&sort_prune_order(resources.clone())), reversed);

        // The same symmetry holds for bare keys (the pruner only ever has keys).
        let key_set: Vec<ResourceKey> = resources.iter().map(|r| r.key.clone()).collect();
        assert_eq!(
            sort_keys_prune_order(key_set.clone()),
            sort_keys_apply_order(key_set)
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
        );

        // Reversing the prune order restores the apply order exactly.
        let mut back = prune;
        back.reverse();
        assert_eq!(keys(&back), keys(&apply));
    }

    /// **Verification:** the order depends only on the input *set*, never on iteration order.
    #[test]
    fn ordering_is_deterministic_across_every_permutation_shape() {
        let base = one_per_tier();
        let expected = keys(&sort_apply_order(base.clone()));

        // Deterministic pseudo-random shuffles (no RNG dependency, reproducible on failure).
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };

        for round in 0..64 {
            let mut shuffled = base.clone();
            for index in (1..shuffled.len()).rev() {
                let swap_with = (next() as usize) % (index + 1);
                shuffled.swap(index, swap_with);
            }
            assert_eq!(
                keys(&sort_apply_order(shuffled.clone())),
                expected,
                "round {round}"
            );
            let mut reversed = expected.clone();
            reversed.reverse();
            assert_eq!(
                keys(&sort_prune_order(shuffled)),
                reversed,
                "prune round {round}"
            );
        }

        // Reversed input and a rotating input are both stable.
        let mut reversed_input = base.clone();
        reversed_input.reverse();
        assert_eq!(keys(&sort_apply_order(reversed_input)), expected);
        for rotation in 0..base.len() {
            let mut rotated = base.clone();
            rotated.rotate_left(rotation);
            assert_eq!(keys(&sort_apply_order(rotated)), expected);
        }
    }

    #[test]
    fn sorting_is_stable_for_empty_and_singleton_inputs() {
        assert!(sort_apply_order(Vec::new()).is_empty());
        assert!(sort_prune_order(Vec::new()).is_empty());
        assert!(sort_keys_apply_order(Vec::new()).is_empty());
        assert!(sort_keys_prune_order(Vec::new()).is_empty());

        let single = resource("", "ConfigMap", Some("team-a"), "settings");
        assert_eq!(
            keys(&sort_apply_order(vec![single.clone()])),
            keys(&sort_prune_order(vec![single]))
        );

        // The backwards-compatible alias keeps the documented contract.
        let resources = one_per_tier();
        assert_eq!(
            keys(&sort_by_tier(resources.clone())),
            keys(&sort_apply_order(resources))
        );
    }
}
