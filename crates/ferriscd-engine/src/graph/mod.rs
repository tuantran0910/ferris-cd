//! Dependency-aware ordering of desired resources.
//!
//! Phase 03 ships the minimal deterministic four-tier sorter required for `v0.1`
//! and `v0.2` (multi-file repos must not apply a `Deployment` before its
//! `Namespace` just because of filesystem order). The function is deliberately
//! small so Phase 08/10 can grow it into the full sync-wave / lifecycle-hook
//! graph without changing the ordering contract.

use crate::manifest::types::DesiredResource;

/// Deterministic apply tier for a resource.
///
/// * Tier 0: `Namespace`
/// * Tier 1: `CustomResourceDefinition`
/// * Tier 2: `ServiceAccount`, `Role`, `ClusterRole`, `RoleBinding`,
///   `ClusterRoleBinding`, `ConfigMap`, `Secret`
/// * Tier 3: everything else
#[must_use]
pub fn tier(resource: &DesiredResource) -> u8 {
    // Phase 03 keys tiers on `kind` alone (not `group`): scope/ownership information from
    // Discovery is not yet available to the offline sorter, and kind-level ordering already
    // covers the `Namespace`-before-`Deployment` hazard this milestone targets.
    match resource.gvk.kind.as_str() {
        "Namespace" => 0,
        "CustomResourceDefinition" => 1,
        "ServiceAccount" | "Role" | "ClusterRole" | "RoleBinding" | "ClusterRoleBinding"
        | "ConfigMap" | "Secret" => 2,
        _ => 3,
    }
}

/// Sorts resources by [`tier`], tie-breaking deterministically by [`ResourceKey`].
#[must_use]
pub fn sort_by_tier(mut resources: Vec<DesiredResource>) -> Vec<DesiredResource> {
    resources.sort_by(|a, b| tier(a).cmp(&tier(b)).then_with(|| a.key.cmp(&b.key)));
    resources
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::manifest::types::{GroupVersionKind, ResourceKey};

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

    #[test]
    fn reversed_input_yields_exact_tier_order_with_deterministic_ties() {
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
                (0, "Namespace", "ferriscd-demo"),
                (1, "CustomResourceDefinition", "widgets"),
                (2, "ConfigMap", "demo-config"),
                // Tier 3 tie-break: core group ("") sorts before "apps".
                (3, "Service", "demo-app"),
                (3, "Deployment", "demo-app"),
            ]
        );
    }

    #[test]
    fn tier_assignment_covers_every_tier() {
        assert_eq!(tier(&resource("", "Namespace", "n")), 0);
        assert_eq!(
            tier(&resource(
                "apiextensions.k8s.io",
                "CustomResourceDefinition",
                "crd"
            )),
            1
        );
        for kind in [
            "ServiceAccount",
            "Role",
            "ClusterRole",
            "RoleBinding",
            "ClusterRoleBinding",
            "ConfigMap",
            "Secret",
        ] {
            assert_eq!(tier(&resource("", kind, "x")), 2, "kind {kind}");
        }
        assert_eq!(tier(&resource("apps", "Deployment", "d")), 3);
        assert_eq!(tier(&resource("", "Pod", "p")), 3);
    }
}
