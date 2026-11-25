//! Dependency-aware ordering of desired resources.
//!
//! Phase 03 shipped a minimal four-tier sorter; **T08.1** grew it into the full twelve-tier
//! Kubernetes priority order ([`order`]) with a deterministic [`ResourceKey`] tie-break, plus the
//! prune order as the exact reverse of the apply order.
//!
//! ```text
//! Namespace (0) -> ResourceQuota/LimitRange (1) -> CustomResourceDefinition (2)
//!   -> ServiceAccount (3) -> Role/ClusterRole (4) -> RoleBinding/ClusterRoleBinding (5)
//!   -> ConfigMap/Secret (6) -> StorageClass/PVC (7) -> Service (8)
//!   -> Deployment/StatefulSet/DaemonSet/Job/CronJob (9)
//!   -> Ingress/NetworkPolicy/HPA/PDB (10) -> custom resources & webhooks (11)
//! ```
//!
//! Apply order and prune order are two views of one ordering, so a resource that had to exist
//! first is deleted last. Sync *waves* (Phase 10) sort ascending by wave and then use this
//! ordering inside each wave; nothing here needs to change when that lands.

pub mod order;

pub use order::{
    APIEXTENSIONS_GROUP, CRD_KIND, MAX_TIER, TIER_CONFIG, TIER_CRD, TIER_CUSTOM_RESOURCE,
    TIER_EDGE, TIER_NAMESPACE, TIER_QUOTA, TIER_RBAC_BINDING, TIER_RBAC_ROLE, TIER_SERVICE,
    TIER_SERVICE_ACCOUNT, TIER_STORAGE, TIER_WORKLOAD, TIERS, apply_cmp, is_crd_key,
    is_namespace_key, key_tier, sort_apply_order, sort_by_tier, sort_keys_apply_order,
    sort_keys_prune_order, sort_prune_order, tier, tier_of,
};

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::manifest::types::{DesiredResource, GroupVersionKind, ResourceKey};

    fn resource(group: &str, kind: &str, name: &str) -> DesiredResource {
        let api_version = if group.is_empty() {
            "v1".to_owned()
        } else {
            format!("{group}/v1")
        };
        let object = serde_json::from_value(json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": { "name": name }
        }))
        .expect("valid DynamicObject");
        DesiredResource {
            key: ResourceKey::new(group, kind, None, name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("parse gvk"),
            object,
            source_file: "fixture.yaml".to_owned(),
        }
    }

    /// The module-level contract: the re-exports are the ordering module's API, and a
    /// `Namespace` before a `Deployment` still holds after the twelve-tier expansion.
    #[test]
    fn reexported_order_puts_namespace_before_workload() {
        let input = vec![
            resource("apps", "Deployment", "demo-app"),
            resource("", "Service", "demo-app"),
            resource("", "ConfigMap", "demo-config"),
            resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                "widgets",
            ),
            resource("", "Namespace", "ferriscd-demo"),
        ];

        let sorted = sort_by_tier(input);
        let order: Vec<(u8, &str, &str)> = sorted
            .iter()
            .map(|r| (tier(r), r.gvk.kind.as_str(), r.key.name.as_str()))
            .collect();
        assert_eq!(
            order,
            vec![
                (TIER_NAMESPACE, "Namespace", "ferriscd-demo"),
                (TIER_CRD, "CustomResourceDefinition", "widgets"),
                (TIER_CONFIG, "ConfigMap", "demo-config"),
                (TIER_SERVICE, "Service", "demo-app"),
                (TIER_WORKLOAD, "Deployment", "demo-app"),
            ]
        );
    }
}
