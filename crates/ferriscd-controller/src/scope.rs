//! Cluster-aware scope normalization.
//!
//! Offline normalization deliberately refuses to guess whether a custom resource is
//! namespaced or cluster-scoped (review finding H1): only the API server — or the
//! `CustomResourceDefinition` sitting in the same bundle — knows. This stage therefore runs
//! immediately before diffing/applying and resolves every resource's scope in this order:
//!
//! 1. the [`DiscoveryCache`](crate::discovery::DiscoveryCache) snapshot,
//! 2. a `CustomResourceDefinition` in the same bundle whose `spec.group` + `spec.names.kind`
//!    match (the CRD + CR single-sync case, trap T6).
//!
//! Then:
//!
//! * **namespaced without `metadata.namespace`** → inject `spec.destination.namespace` and
//!   update [`ResourceKey::namespace`](ferriscd_engine::manifest::ResourceKey),
//! * **namespaced with `metadata.namespace`** → preserved (never overwritten),
//! * **cluster-scoped** → never injected; a non-empty `metadata.namespace` is a validation
//!   error (or is stripped when the caller explicitly opts in), and the key namespace stays
//!   `None`.
//!
//! Validation happens for the whole bundle **before** any mutation, so a bad resource can
//! never leave the set half-normalized. Note that a `CustomResourceDefinition` object in
//! the bundle is itself resolved through discovery first; with a cold discovery index, the
//! CRD's own scope is unknown unless the API server already serves
//! `apiextensions.k8s.io/v1` (it normally does).

use ferriscd_engine::manifest::{DesiredResource, GroupVersionKind};
use kube::discovery::Scope;

use crate::discovery::ScopeLookup;

/// API group of `CustomResourceDefinition` objects.
pub const APIEXTENSIONS_GROUP: &str = "apiextensions.k8s.io";

/// Kind of `CustomResourceDefinition` objects.
pub const CRD_KIND: &str = "CustomResourceDefinition";

/// What to do when a cluster-scoped resource carries `metadata.namespace`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClusterNamespacePolicy {
    /// Reject the bundle with a clear validation error (default: a namespace on a
    /// cluster-scoped resource is almost always a copy/paste bug worth surfacing).
    #[default]
    Error,
    /// Strip the bogus namespace and continue (explicit opt-in only).
    Strip,
}

/// A `CustomResourceDefinition` from the same bundle, reduced to what scoping needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InBundleCrd {
    /// `spec.group`.
    pub group: String,
    /// `spec.names.kind`.
    pub kind: String,
    /// `spec.scope`.
    pub scope: Scope,
}

/// Scope normalization failures.
#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    /// Neither discovery nor an in-bundle CRD knows the resource kind.
    #[error(
        "cannot determine the API scope of {gvk}: the kind is unknown to cluster discovery and \
         no matching CustomResourceDefinition is in the bundle"
    )]
    UnknownScope {
        /// The unresolved `group/version/kind`.
        gvk: String,
    },

    /// A cluster-scoped resource declared a namespace.
    #[error(
        "{resource}: cluster-scoped kind {kind} must not set metadata.namespace ('{namespace}')"
    )]
    ClusterScopedWithNamespace {
        /// Canonical GKNN key of the offending resource.
        resource: String,
        /// Resource kind.
        kind: String,
        /// The namespace that must not be set.
        namespace: String,
    },

    /// A namespaced resource needs a destination namespace, but none was configured.
    #[error(
        "resource {resource} is namespaced and sets no metadata.namespace, so a non-empty destination namespace is required"
    )]
    EmptyDestinationNamespace {
        /// Canonical GKNN key of the offending resource.
        resource: String,
    },

    /// An in-bundle `CustomResourceDefinition` is missing scoping information.
    #[error("CustomResourceDefinition {resource} is malformed: {message}")]
    MalformedCrd {
        /// Object name (or source file when unnamed).
        resource: String,
        /// What went wrong.
        message: String,
    },
}

/// Extracts the scoping information of every in-bundle `CustomResourceDefinition`.
///
/// CRDs are applied before custom resources, so a CR whose CRD is in the same bundle
/// resolves even when the CRD does not exist in the cluster yet (trap T6).
///
/// # Errors
///
/// [`ScopeError::MalformedCrd`] when `spec.group`, `spec.names.kind`, or `spec.scope` is
/// missing or has the wrong type.
pub fn collect_in_bundle_crds(
    resources: &[DesiredResource],
) -> Result<Vec<InBundleCrd>, ScopeError> {
    let mut crds = Vec::new();
    for resource in resources {
        if resource.gvk.group != APIEXTENSIONS_GROUP || resource.gvk.kind != CRD_KIND {
            continue;
        }
        let name = resource.key.name.clone();
        let spec = resource
            .object
            .data
            .get("spec")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| ScopeError::MalformedCrd {
                resource: name.clone(),
                message: "spec must be a mapping".to_owned(),
            })?;

        let group = required_str(spec.get("group"), &name, "spec.group")?;
        let kind = spec
            .get("names")
            .and_then(serde_json::Value::as_object)
            .and_then(|names| names.get("kind"))
            .ok_or_else(|| ScopeError::MalformedCrd {
                resource: name.clone(),
                message: "spec.names.kind must be a non-empty string".to_owned(),
            })
            .and_then(|kind| required_str(Some(kind), &name, "spec.names.kind"))?;
        let scope = match required_str(spec.get("scope"), &name, "spec.scope")?.as_str() {
            "Namespaced" | "namespaced" => Scope::Namespaced,
            "Cluster" | "cluster" => Scope::Cluster,
            other => {
                return Err(ScopeError::MalformedCrd {
                    resource: name,
                    message: format!("spec.scope '{other}' is neither Namespaced nor Cluster"),
                });
            }
        };

        crds.push(InBundleCrd { group, kind, scope });
    }
    Ok(crds)
}

fn required_str(
    value: Option<&serde_json::Value>,
    resource: &str,
    field: &str,
) -> Result<String, ScopeError> {
    value
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| ScopeError::MalformedCrd {
            resource: resource.to_owned(),
            message: format!("{field} must be a non-empty string"),
        })
}

/// Resolves the scope of `gvk`, preferring live discovery over the bundle.
///
/// Discovery wins because it reflects what the API server will actually accept; the
/// in-bundle CRD is only a fallback for kinds that are not installed yet.
#[must_use]
pub fn resolve_scope(
    gvk: &GroupVersionKind,
    discovery: &dyn ScopeLookup,
    in_bundle_crds: &[InBundleCrd],
) -> Option<Scope> {
    let discovered = kube::core::gvk::GroupVersionKind::gvk(&gvk.group, &gvk.version, &gvk.kind);
    discovery.scope_of(&discovered).or_else(|| {
        in_bundle_crds
            .iter()
            .find(|crd| crd.group == gvk.group && crd.kind == gvk.kind)
            .map(|crd| crd.scope.clone())
    })
}

/// Normalizes resource scopes, rejecting any cluster-scoped resource that sets a namespace.
///
/// # Errors
///
/// See [`ScopeError`]; the bundle is left untouched when any resource fails validation.
pub fn normalize_scopes(
    resources: &mut [DesiredResource],
    destination_namespace: &str,
    discovery: &dyn ScopeLookup,
    in_bundle_crds: &[InBundleCrd],
) -> Result<(), ScopeError> {
    normalize_scopes_with(
        resources,
        destination_namespace,
        ClusterNamespacePolicy::Error,
        discovery,
        in_bundle_crds,
    )
}

/// [`normalize_scopes`] with an explicit [`ClusterNamespacePolicy`].
///
/// # Errors
///
/// See [`ScopeError`]; the bundle is left untouched when any resource fails validation.
pub fn normalize_scopes_with(
    resources: &mut [DesiredResource],
    destination_namespace: &str,
    cluster_policy: ClusterNamespacePolicy,
    discovery: &dyn ScopeLookup,
    in_bundle_crds: &[InBundleCrd],
) -> Result<(), ScopeError> {
    // Pass 1: resolve and validate everything, planning the exact mutation per resource.
    let mut plans = Vec::with_capacity(resources.len());
    for resource in resources.iter() {
        let scope = resolve_scope(&resource.gvk, discovery, in_bundle_crds).ok_or_else(|| {
            ScopeError::UnknownScope {
                gvk: resource.gvk.to_string(),
            }
        })?;
        let declared = resource
            .object
            .metadata
            .namespace
            .as_deref()
            .map(str::trim)
            .filter(|namespace| !namespace.is_empty());

        let plan = match (scope, declared) {
            (Scope::Namespaced, None) => {
                let destination = destination_namespace.trim();
                if destination.is_empty() {
                    return Err(ScopeError::EmptyDestinationNamespace {
                        resource: resource.key.canonical(),
                    });
                }
                Plan::Inject(destination.to_owned())
            }
            (Scope::Namespaced, Some(namespace)) => Plan::Keep(namespace.to_owned()),
            (Scope::Cluster, None) => Plan::Cluster,
            (Scope::Cluster, Some(namespace)) => match cluster_policy {
                ClusterNamespacePolicy::Error => {
                    return Err(ScopeError::ClusterScopedWithNamespace {
                        resource: resource.key.canonical(),
                        kind: resource.gvk.kind.clone(),
                        namespace: namespace.to_owned(),
                    });
                }
                ClusterNamespacePolicy::Strip => Plan::Cluster,
            },
        };
        plans.push(plan);
    }

    // Pass 2: mutate. Reachable only when every resource validated.
    for (resource, plan) in resources.iter_mut().zip(plans) {
        match plan {
            Plan::Inject(namespace) => {
                resource.object.metadata.namespace = Some(namespace.clone());
                resource.key.namespace = Some(namespace);
            }
            Plan::Keep(namespace) => {
                resource.object.metadata.namespace = Some(namespace.clone());
                resource.key.namespace = Some(namespace);
            }
            Plan::Cluster => {
                resource.object.metadata.namespace = None;
                resource.key.namespace = None;
            }
        }
    }
    Ok(())
}

/// The validated mutation for one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// Namespaced without an explicit namespace: inject the destination namespace.
    Inject(String),
    /// Namespaced with an explicit namespace: keep it and mirror it onto the key.
    Keep(String),
    /// Cluster-scoped: never namespaced.
    Cluster,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ferriscd_engine::manifest::ResourceKey;
    use kube::api::DynamicObject;
    use kube::core::gvk::GroupVersionKind as KubeGvk;
    use serde_json::{Value, json};

    use super::*;

    struct FakeScopes(HashMap<(String, String), Scope>);

    impl FakeScopes {
        fn empty() -> Self {
            Self(HashMap::new())
        }

        fn with(mut self, group: &str, kind: &str, scope: Scope) -> Self {
            self.0.insert((group.to_owned(), kind.to_owned()), scope);
            self
        }
    }

    impl ScopeLookup for FakeScopes {
        fn scope_of(&self, gvk: &KubeGvk) -> Option<Scope> {
            self.0.get(&(gvk.group.clone(), gvk.kind.clone())).cloned()
        }
    }

    fn resource(api_version: &str, kind: &str, value: Value) -> DesiredResource {
        let gvk = GroupVersionKind::parse(api_version, kind).expect("test apiVersion");
        let object: DynamicObject = serde_json::from_value(value).expect("test object");
        let name = object
            .metadata
            .name
            .clone()
            .unwrap_or_else(|| "unnamed".to_owned());
        let key = ResourceKey::new(
            gvk.group.clone(),
            gvk.kind.clone(),
            object.metadata.namespace.clone(),
            name,
        );
        DesiredResource {
            key,
            gvk,
            object,
            source_file: "deploy.yaml".to_owned(),
        }
    }

    fn deployment(namespace: Option<&str>) -> DesiredResource {
        let mut metadata = json!({ "name": "api" });
        if let Some(namespace) = namespace {
            metadata["namespace"] = json!(namespace);
        }
        resource(
            "apps/v1",
            "Deployment",
            json!({ "apiVersion": "apps/v1", "kind": "Deployment", "metadata": metadata }),
        )
    }

    fn cluster_role(namespace: Option<&str>) -> DesiredResource {
        let mut metadata = json!({ "name": "reader" });
        if let Some(namespace) = namespace {
            metadata["namespace"] = json!(namespace);
        }
        resource(
            "rbac.authorization.k8s.io/v1",
            "ClusterRole",
            json!({
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": metadata,
                "rules": [],
            }),
        )
    }

    fn crd(scope: &str) -> DesiredResource {
        resource(
            "apiextensions.k8s.io/v1",
            "CustomResourceDefinition",
            json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.com" },
                "spec": {
                    "group": "example.com",
                    "names": { "kind": "Widget", "plural": "widgets" },
                    "scope": scope,
                    "versions": [],
                },
            }),
        )
    }

    fn widget(namespace: Option<&str>) -> DesiredResource {
        let mut metadata = json!({ "name": "widget-a" });
        if let Some(namespace) = namespace {
            metadata["namespace"] = json!(namespace);
        }
        resource(
            "example.com/v1",
            "Widget",
            json!({ "apiVersion": "example.com/v1", "kind": "Widget", "metadata": metadata }),
        )
    }

    fn discovery() -> FakeScopes {
        FakeScopes::empty()
            .with("apps", "Deployment", Scope::Namespaced)
            .with("rbac.authorization.k8s.io", "ClusterRole", Scope::Cluster)
            .with(APIEXTENSIONS_GROUP, CRD_KIND, Scope::Cluster)
    }

    #[test]
    fn namespaced_resource_gets_the_destination_namespace() {
        let mut resources = vec![deployment(None)];
        normalize_scopes(&mut resources, "payments", &discovery(), &[]).expect("normalize");

        assert_eq!(
            resources[0].object.metadata.namespace.as_deref(),
            Some("payments")
        );
        assert_eq!(resources[0].key.namespace.as_deref(), Some("payments"));
        assert_eq!(resources[0].key.canonical(), "apps/Deployment/payments/api");
    }

    #[test]
    fn explicit_namespace_is_preserved() {
        let mut resources = vec![deployment(Some("team-a"))];
        normalize_scopes(&mut resources, "payments", &discovery(), &[]).expect("normalize");

        assert_eq!(
            resources[0].object.metadata.namespace.as_deref(),
            Some("team-a"),
            "an explicit namespace must never be overwritten by the destination"
        );
        assert_eq!(resources[0].key.namespace.as_deref(), Some("team-a"));
    }

    #[test]
    fn cluster_scoped_resources_are_never_namespaced() {
        let mut resources = vec![cluster_role(None)];
        normalize_scopes(&mut resources, "payments", &discovery(), &[]).expect("normalize");

        assert_eq!(resources[0].object.metadata.namespace, None);
        assert_eq!(resources[0].key.namespace, None);
        assert_eq!(
            resources[0].key.canonical(),
            "rbac.authorization.k8s.io/ClusterRole//reader"
        );
    }

    #[test]
    fn cluster_scoped_resource_with_a_namespace_is_rejected_by_default() {
        let mut resources = vec![cluster_role(Some("payments"))];
        let err = normalize_scopes(&mut resources, "payments", &discovery(), &[])
            .expect_err("cluster-scoped resource with a namespace must be rejected");

        let text = err.to_string();
        assert!(text.contains("ClusterRole"), "{text}");
        assert!(text.contains("payments"), "{text}");
        assert!(matches!(
            err,
            ScopeError::ClusterScopedWithNamespace { ref kind, .. } if kind == "ClusterRole"
        ));
    }

    #[test]
    fn cluster_scoped_resource_with_a_namespace_is_stripped_when_configured() {
        let mut resources = vec![cluster_role(Some("payments"))];
        normalize_scopes_with(
            &mut resources,
            "payments",
            ClusterNamespacePolicy::Strip,
            &discovery(),
            &[],
        )
        .expect("strip policy must clear the namespace");

        assert_eq!(resources[0].object.metadata.namespace, None);
        assert_eq!(resources[0].key.namespace, None);
    }

    #[test]
    fn in_bundle_crd_supplies_the_scope_of_an_uninstalled_kind() {
        let mut crds = [crd("Cluster"), widget(None)];
        let in_bundle = collect_in_bundle_crds(&crds).expect("collect CRDs");
        assert_eq!(
            in_bundle,
            vec![InBundleCrd {
                group: "example.com".to_owned(),
                kind: "Widget".to_owned(),
                scope: Scope::Cluster,
            }]
        );

        // Discovery does not know `example.com/v1 Widget` yet (the CRD is in the same bundle).
        normalize_scopes(&mut crds, "payments", &discovery(), &in_bundle).expect("normalize");

        assert_eq!(crds[1].object.metadata.namespace, None);
        assert_eq!(crds[1].key.namespace, None);
        // The CRD itself is cluster-scoped too.
        assert_eq!(crds[0].object.metadata.namespace, None);
    }

    #[test]
    fn in_bundle_namespaced_crd_injects_the_destination_namespace() {
        let mut resources = [crd("Namespaced"), widget(None)];
        let in_bundle = collect_in_bundle_crds(&resources).expect("collect CRDs");

        normalize_scopes(&mut resources, "payments", &discovery(), &in_bundle).expect("normalize");

        assert_eq!(
            resources[1].object.metadata.namespace.as_deref(),
            Some("payments")
        );
        assert_eq!(resources[1].key.namespace.as_deref(), Some("payments"));
    }

    #[test]
    fn discovery_takes_precedence_over_the_in_bundle_crd() {
        let live = FakeScopes::empty().with("example.com", "Widget", Scope::Namespaced);
        let in_bundle = [InBundleCrd {
            group: "example.com".to_owned(),
            kind: "Widget".to_owned(),
            scope: Scope::Cluster,
        }];

        assert_eq!(
            resolve_scope(
                &GroupVersionKind::parse("example.com/v1", "Widget").expect("gvk"),
                &live,
                &in_bundle
            ),
            Some(Scope::Namespaced),
            "live discovery reflects what the API server accepts and must win"
        );
    }

    #[test]
    fn unknown_scopes_are_an_explicit_error() {
        let mut resources = vec![widget(None)];
        let err = normalize_scopes(&mut resources, "payments", &discovery(), &[])
            .expect_err("unknown kinds must not be guessed");
        assert!(matches!(err, ScopeError::UnknownScope { .. }));
        assert!(err.to_string().contains("example.com/v1/Widget"), "{err}");
        assert_eq!(
            resources[0].object.metadata.namespace, None,
            "the resource must be untouched"
        );
    }

    #[test]
    fn an_empty_destination_namespace_is_rejected_for_namespaced_resources() {
        let mut resources = vec![deployment(None)];
        let err = normalize_scopes(&mut resources, "   ", &discovery(), &[])
            .expect_err("namespaced resources need a destination namespace");
        assert!(matches!(err, ScopeError::EmptyDestinationNamespace { .. }));
        assert_eq!(resources[0].object.metadata.namespace, None);
    }

    #[test]
    fn validation_failures_leave_the_bundle_untouched() {
        // First resource would be mutated, second is invalid: the whole bundle must stay
        // as it was, so a retry cannot operate on a half-normalized set.
        let mut resources = vec![deployment(None), cluster_role(Some("payments"))];
        normalize_scopes(&mut resources, "payments", &discovery(), &[])
            .expect_err("invalid bundle");

        assert_eq!(
            resources[0].object.metadata.namespace, None,
            "no partial mutation is allowed"
        );
        assert_eq!(resources[0].key.namespace, None);
        assert_eq!(
            resources[1].object.metadata.namespace.as_deref(),
            Some("payments")
        );
    }

    #[test]
    fn malformed_crds_are_reported() {
        let broken = resource(
            "apiextensions.k8s.io/v1",
            "CustomResourceDefinition",
            json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.com" },
                "spec": { "group": "example.com", "names": { "kind": "Widget" } },
            }),
        );
        let err = collect_in_bundle_crds(&[broken]).expect_err("missing spec.scope");
        assert!(matches!(err, ScopeError::MalformedCrd { .. }));
        assert!(err.to_string().contains("spec.scope"), "{err}");

        let bad_scope = resource(
            "apiextensions.k8s.io/v1",
            "CustomResourceDefinition",
            json!({
                "apiVersion": "apiextensions.k8s.io/v1",
                "kind": "CustomResourceDefinition",
                "metadata": { "name": "widgets.example.com" },
                "spec": {
                    "group": "example.com",
                    "names": { "kind": "Widget" },
                    "scope": "Global",
                },
            }),
        );
        let err = collect_in_bundle_crds(&[bad_scope]).expect_err("bad spec.scope");
        assert!(err.to_string().contains("Global"), "{err}");
    }
}
