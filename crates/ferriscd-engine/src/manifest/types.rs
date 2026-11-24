//! Version-agnostic resource identity and the desired-resource model.
//!
//! [`ResourceKey`] intentionally omits the API `version` (and therefore the full
//! GVK) from equality/hash/ordering so a Kubernetes API upgrade such as
//! `networking.k8s.io/v1beta1` -> `networking.k8s.io/v1` never changes the
//! identity of an already-managed object. This is the property that prevents
//! self-pruning during API version migrations (ADR-003).

use std::fmt;

use kube::api::DynamicObject;

/// Version-agnostic Kubernetes resource identity over **Group + Kind + Namespace + Name**
/// (GKNN). The API `version` is deliberately not part of the key.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceKey {
    /// API group (empty for the core group).
    pub group: String,
    /// Resource kind (PascalCase, e.g. `Deployment`).
    pub kind: String,
    /// Namespace; `None` for cluster-scoped resources.
    pub namespace: Option<String>,
    /// Object name.
    pub name: String,
}

impl ResourceKey {
    /// Constructs a new [`ResourceKey`].
    #[must_use]
    pub fn new(
        group: impl Into<String>,
        kind: impl Into<String>,
        namespace: Option<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            group: group.into(),
            kind: kind.into(),
            namespace,
            name: name.into(),
        }
    }

    /// Canonical GKNN string `<group>/<kind>/<namespace>/<name>`.
    ///
    /// Cluster-scoped resources use an empty namespace segment, e.g.
    /// `rbac.authorization.k8s.io/ClusterRole//ferriscd-admin`.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.group,
            self.kind,
            self.namespace.as_deref().unwrap_or(""),
            self.name
        )
    }
}

impl fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// A parsed Kubernetes `apiVersion`/`kind` pair (group + version + kind).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupVersionKind {
    /// API group (empty for the core group).
    pub group: String,
    /// API version (e.g. `v1`).
    pub version: String,
    /// Resource kind.
    pub kind: String,
}

impl GroupVersionKind {
    /// Parses an `apiVersion` string into `(group, version)`.
    ///
    /// * `"v1"` -> `{ group: "", version: "v1" }`
    /// * `"apps/v1"` -> `{ group: "apps", version: "v1" }`
    ///
    /// Returns `None` for an empty `apiVersion`, an empty group/version segment,
    /// or more than one `/` separator.
    #[must_use]
    pub fn parse(api_version: &str, kind: &str) -> Option<Self> {
        let (group, version) = match api_version.split_once('/') {
            Some((group, version)) => {
                if group.is_empty() || version.is_empty() || version.contains('/') {
                    return None;
                }
                (group, version)
            }
            None => {
                if api_version.is_empty() {
                    return None;
                }
                ("", api_version)
            }
        };

        Some(Self {
            group: group.to_owned(),
            version: version.to_owned(),
            kind: kind.to_owned(),
        })
    }
}

impl fmt::Display for GroupVersionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.group.is_empty() {
            write!(f, "{}/{}", self.version, self.kind)
        } else {
            write!(f, "{}/{}/{}", self.group, self.version, self.kind)
        }
    }
}

/// A single desired Kubernetes object, its identity, and provenance.
#[derive(Clone, Debug)]
pub struct DesiredResource {
    /// Version-agnostic identity (GKNN).
    pub key: ResourceKey,
    /// The parsed `apiVersion`/`kind`.
    pub gvk: GroupVersionKind,
    /// The normalized desired object payload.
    pub object: DynamicObject,
    /// Repository-relative source file path this resource was loaded from.
    pub source_file: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_key_identity_is_version_agnostic() {
        // Two Ingresses that differ ONLY in apiVersion share a ResourceKey: the key has no
        // version field at all, which is exactly the invariant ADR-003 requires.
        let v1beta1 = ResourceKey::new(
            "networking.k8s.io",
            "Ingress",
            Some("payments".to_owned()),
            "web",
        );
        let v1 = ResourceKey::new(
            "networking.k8s.io",
            "Ingress",
            Some("payments".to_owned()),
            "web",
        );

        assert_eq!(v1beta1, v1);
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let hash = |key: &ResourceKey| {
            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(hash(&v1beta1), hash(&v1));

        // The corresponding GVKs still differ by version (stored only as a non-key hint).
        let gvk_beta = GroupVersionKind::parse("networking.k8s.io/v1beta1", "Ingress")
            .expect("valid apiVersion");
        let gvk_v1 =
            GroupVersionKind::parse("networking.k8s.io/v1", "Ingress").expect("valid apiVersion");
        assert_ne!(gvk_beta.version, gvk_v1.version);
    }

    #[test]
    fn resource_key_distinguishes_every_gknn_component() {
        let base = ResourceKey::new("apps", "Deployment", Some("ns".to_owned()), "api");

        let different_group =
            ResourceKey::new("extensions", "Deployment", Some("ns".to_owned()), "api");
        let different_kind = ResourceKey::new("apps", "StatefulSet", Some("ns".to_owned()), "api");
        let different_ns = ResourceKey::new("apps", "Deployment", Some("other".to_owned()), "api");
        let different_name = ResourceKey::new("apps", "Deployment", Some("ns".to_owned()), "web");

        for other in [
            different_group,
            different_kind,
            different_ns,
            different_name,
        ] {
            assert_ne!(base, other);
        }

        // Cluster-scoped vs namespaced identity must also differ.
        let cluster_scoped = ResourceKey::new("apps", "Deployment", None, "api");
        assert_ne!(base, cluster_scoped);
    }

    #[test]
    fn group_version_kind_parse_handles_core_and_grouped_versions() {
        let core = GroupVersionKind::parse("v1", "ConfigMap").expect("core apiVersion");
        assert_eq!(core.group, "");
        assert_eq!(core.version, "v1");
        assert_eq!(core.kind, "ConfigMap");

        let grouped = GroupVersionKind::parse("apps/v1", "Deployment").expect("grouped apiVersion");
        assert_eq!(grouped.group, "apps");
        assert_eq!(grouped.version, "v1");
        assert_eq!(grouped.kind, "Deployment");
    }

    #[test]
    fn group_version_kind_parse_rejects_malformed_api_versions() {
        for api_version in ["", "/v1", "apps/", "apps/v1/beta", "apps/v1/"] {
            assert!(
                GroupVersionKind::parse(api_version, "X").is_none(),
                "expected {api_version:?} to be rejected"
            );
        }
    }

    #[test]
    fn canonical_key_formats_group_kind_namespace_name() {
        let namespaced = ResourceKey::new("apps", "Deployment", Some("prod".to_owned()), "api");
        assert_eq!(namespaced.canonical(), "apps/Deployment/prod/api");
        assert_eq!(namespaced.to_string(), "apps/Deployment/prod/api");

        let cluster = ResourceKey::new("rbac.authorization.k8s.io", "ClusterRole", None, "admin");
        assert_eq!(
            cluster.canonical(),
            "rbac.authorization.k8s.io/ClusterRole//admin"
        );

        let core = ResourceKey::new("", "Service", Some("default".to_owned()), "demo");
        assert_eq!(core.canonical(), "/Service/default/demo");
    }

    #[test]
    fn group_version_kind_display() {
        assert_eq!(
            GroupVersionKind::parse("v1", "Secret")
                .expect("parse")
                .to_string(),
            "v1/Secret"
        );
        assert_eq!(
            GroupVersionKind::parse("apps/v1", "Deployment")
                .expect("parse")
                .to_string(),
            "apps/v1/Deployment"
        );
    }
}
