//! `AppProject` custom resource: the multi-tenancy boundary for `Application` objects.
//!
//! Through `v0.4`, `Application` and `AppProject` both live in the control-plane
//! namespace ([`CONTROL_PLANE_NAMESPACE`]). [`AppProjectSpec::source_namespaces`] is the
//! opt-in extension point for Apps-in-any-namespace (Phase 12), and
//! [`AppProjectSpec::allowed_service_accounts`] bounds which `serviceAccountName` values a
//! tenant may request (review findings C8 and M6).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::CONTROL_PLANE_NAMESPACE;
use crate::application::DEFAULT_DESTINATION_CLUSTER;
use crate::status::Condition;

/// Wildcard entry matching every group, kind, namespace, repository, or ServiceAccount.
pub const WILDCARD: &str = "*";

/// Namespaces that may host `Application` objects referencing this project by default.
pub const DEFAULT_SOURCE_NAMESPACES: [&str; 1] = [CONTROL_PLANE_NAMESPACE];

/// `AppProject` custom resource (`ferriscd.io/v1alpha1`).
#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[kube(
    group = "ferriscd.io",
    version = "v1alpha1",
    kind = "AppProject",
    namespaced,
    status = "AppProjectStatus",
    shortname = "proj",
    doc = "Tenancy boundary describing the repositories, clusters, namespaces, GroupKinds, and ServiceAccounts an Application may use",
    derive = "PartialEq"
)]
#[serde(rename_all = "camelCase")]
pub struct AppProjectSpec {
    /// Free-form description of the project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Allowed source repositories (`*` matches everything, `!prefix` denies).
    #[serde(default)]
    pub source_repos: Vec<String>,

    /// Namespaces allowed to host `Application` objects that reference this project.
    ///
    /// Defaults to `["ferriscd-system"]`; widening it is what enables Phase 12
    /// Apps-in-any-namespace, which then requires `allowedServiceAccounts`.
    #[serde(default = "default_source_namespaces")]
    pub source_namespaces: Vec<String>,

    /// Allowed `(cluster, namespace)` destinations. `namespace: "*"` allows any namespace.
    #[serde(default)]
    pub destinations: Vec<ProjectDestination>,

    /// Cluster-scoped GroupKinds this project may manage (`group: "*"`, `kind: "*"` wildcards).
    #[serde(default)]
    pub cluster_resource_whitelist: Vec<GroupKind>,

    /// Namespaced GroupKinds this project may manage.
    #[serde(default)]
    pub namespace_resource_whitelist: Vec<GroupKind>,

    /// Namespaced GroupKinds explicitly denied even if a whitelist would allow them.
    #[serde(default)]
    pub namespace_resource_blacklist: Vec<GroupKind>,

    /// ServiceAccounts (`namespace/name` or `namespace:*`) a project may impersonate.
    ///
    /// Empty means "no impersonation allowed"; an `Application` that sets
    /// `spec.serviceAccountName` is rejected unless its project lists it here.
    #[serde(default)]
    pub allowed_service_accounts: Vec<String>,
}

fn default_source_namespaces() -> Vec<String> {
    DEFAULT_SOURCE_NAMESPACES
        .iter()
        .map(|namespace| (*namespace).to_owned())
        .collect()
}

/// Cluster/namespace destination allowed by a project.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectDestination {
    /// Target cluster: `in-cluster` or a FerrisCD cluster Secret name (`*` for any).
    #[serde(default = "default_destination_cluster")]
    pub cluster: String,

    /// Target namespace (`*` for any namespace).
    pub namespace: String,
}

fn default_destination_cluster() -> String {
    DEFAULT_DESTINATION_CLUSTER.to_owned()
}

/// Group/Kind pair used by project allow/deny lists.
#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct GroupKind {
    /// API group; the empty string means the core group, [`WILDCARD`] matches every group.
    #[serde(default)]
    pub group: String,

    /// Kind, or [`WILDCARD`].
    pub kind: String,
}

impl GroupKind {
    /// Builds a `GroupKind`.
    #[must_use]
    pub fn new(group: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            group: group.into(),
            kind: kind.into(),
        }
    }
}

/// `AppProject` `/status` subresource.
///
/// Kept intentionally small: policy evaluation errors are surfaced as `Ready`
/// conditions so a broken project is never silent.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppProjectStatus {
    /// `metadata.generation` observed by the last policy evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Standard conditions describing project validity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

/// Permissive policy stub used from Phase 05 until the real `AppProjectPolicy` lands in Phase 12.
///
/// Every check allows everything on purpose: Phases 05–11 build the sync pipeline before
/// multi-tenancy rules exist. The type is the single swap point —
/// `AppProjectPolicy` replaces it in `T12.1` without touching call sites — and it is
/// deliberately infallible so policy checks can never mask a sync error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PermissivePolicy;

impl PermissivePolicy {
    /// Allows every source repository.
    #[must_use]
    pub fn allows_source_repo(&self, _repo_url: &str) -> bool {
        true
    }

    /// Allows every cluster/namespace destination.
    #[must_use]
    pub fn allows_destination(&self, _destination: &ProjectDestination) -> bool {
        true
    }

    /// Allows every cluster-scoped GroupKind.
    #[must_use]
    pub fn allows_cluster_resource(&self, _group_kind: &GroupKind) -> bool {
        true
    }

    /// Allows every namespaced GroupKind.
    #[must_use]
    pub fn allows_namespace_resource(&self, _group_kind: &GroupKind) -> bool {
        true
    }

    /// Allows every ServiceAccount impersonation.
    #[must_use]
    pub fn allows_service_account(&self, _namespace: &str, _service_account: &str) -> bool {
        true
    }

    /// Allows `Application` objects in every namespace.
    #[must_use]
    pub fn allows_source_namespace(&self, _namespace: &str) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::DEFAULT_PROJECT_NAME;

    const DEFAULT_PROJECT_MANIFEST: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/manifests/default-project.yaml"
    ));

    const FULL_PROJECT: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  description: Payments team
  sourceRepos:
    - https://github.com/example/payments.git
  sourceNamespaces:
    - ferriscd-system
    - payments-system
  destinations:
    - cluster: in-cluster
      namespace: payments
    - cluster: prod-west
      namespace: "*"
  clusterResourceWhitelist:
    - group: rbac.authorization.k8s.io
      kind: ClusterRole
  namespaceResourceWhitelist:
    - group: apps
      kind: Deployment
    - group: ""
      kind: ConfigMap
  namespaceResourceBlacklist:
    - group: ""
      kind: Secret
  allowedServiceAccounts:
    - payments/payments-sa
"#;

    fn parse(yaml: &str) -> AppProject {
        serde_saphyr::from_str(yaml).expect("appproject yaml must parse")
    }

    #[test]
    fn appproject_yaml_round_trips_with_camel_case_field_names() {
        let project = parse(FULL_PROJECT);
        let spec = &project.spec;
        assert_eq!(spec.description.as_deref(), Some("Payments team"));
        assert_eq!(
            spec.source_repos,
            vec!["https://github.com/example/payments.git"]
        );
        assert_eq!(
            spec.source_namespaces,
            vec!["ferriscd-system", "payments-system"]
        );
        assert_eq!(spec.destinations.len(), 2);
        assert_eq!(spec.destinations[1].cluster, "prod-west");
        assert_eq!(spec.destinations[1].namespace, WILDCARD);
        assert_eq!(
            spec.namespace_resource_whitelist[1],
            GroupKind::new("", "ConfigMap")
        );
        assert_eq!(
            spec.namespace_resource_blacklist,
            vec![GroupKind::new("", "Secret")]
        );
        assert_eq!(spec.allowed_service_accounts, vec!["payments/payments-sa"]);

        let serialized = serde_saphyr::to_string(&project).expect("project must serialize");
        assert_eq!(parse(&serialized), project);

        let value: Value = serde_json::to_value(&project).expect("project must serialize to json");
        let spec = &value["spec"];
        assert_eq!(
            spec["sourceRepos"][0],
            json!("https://github.com/example/payments.git")
        );
        assert_eq!(spec["sourceNamespaces"][1], json!("payments-system"));
        assert_eq!(
            spec["clusterResourceWhitelist"][0]["kind"],
            json!("ClusterRole")
        );
        assert_eq!(
            spec["allowedServiceAccounts"][0],
            json!("payments/payments-sa")
        );
        assert!(spec.get("source_repos").is_none());
        assert!(spec.get("allowed_service_accounts").is_none());
    }

    #[test]
    fn source_namespaces_defaults_to_control_plane_namespace() {
        let project = parse(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: minimal
spec: {}
"#,
        );
        assert_eq!(project.spec.source_namespaces, vec!["ferriscd-system"]);
        assert!(project.spec.source_repos.is_empty());
        assert!(project.spec.destinations.is_empty());
        assert!(project.spec.cluster_resource_whitelist.is_empty());
        assert!(project.spec.namespace_resource_whitelist.is_empty());
        assert!(project.spec.namespace_resource_blacklist.is_empty());
        assert!(project.spec.allowed_service_accounts.is_empty());
        assert_eq!(project.status, None);
    }

    #[test]
    fn appproject_schema_generates_with_all_allow_deny_lists() {
        let schema = serde_json::to_value(schemars::schema_for!(AppProjectSpec))
            .expect("schema must serialize");
        let properties = schema["properties"]
            .as_object()
            .expect("properties must be an object");
        for expected in [
            "description",
            "sourceRepos",
            "sourceNamespaces",
            "destinations",
            "clusterResourceWhitelist",
            "namespaceResourceWhitelist",
            "namespaceResourceBlacklist",
            "allowedServiceAccounts",
        ] {
            assert!(
                properties.contains_key(expected),
                "schema is missing {expected}"
            );
        }

        let group_kind = &schema["$defs"]["GroupKind"]["properties"];
        assert!(group_kind.get("group").is_some());
        assert!(group_kind.get("kind").is_some());
    }

    #[test]
    fn default_project_manifest_parses_to_expected_defaults() {
        let project: AppProject =
            serde_saphyr::from_str(DEFAULT_PROJECT_MANIFEST).expect("default project must parse");
        assert_eq!(project.metadata.name.as_deref(), Some(DEFAULT_PROJECT_NAME));
        assert_eq!(
            project.metadata.namespace.as_deref(),
            Some(CONTROL_PLANE_NAMESPACE)
        );

        let spec = project.spec;
        // `sourceNamespaces` is omitted in the manifest, so it comes from the schema default.
        assert_eq!(spec.source_namespaces, vec![CONTROL_PLANE_NAMESPACE]);
        assert_eq!(spec.source_repos, vec![WILDCARD]);
        assert_eq!(spec.destinations.len(), 1);
        assert_eq!(spec.destinations[0].cluster, DEFAULT_DESTINATION_CLUSTER);
        assert_eq!(spec.destinations[0].namespace, WILDCARD);
        assert_eq!(
            spec.cluster_resource_whitelist,
            vec![GroupKind::new(WILDCARD, WILDCARD)]
        );
        assert_eq!(
            spec.namespace_resource_whitelist,
            vec![GroupKind::new(WILDCARD, WILDCARD)]
        );
        assert!(spec.namespace_resource_blacklist.is_empty());
        assert_eq!(spec.allowed_service_accounts, vec![WILDCARD]);
        assert!(
            spec.description
                .as_deref()
                .is_some_and(|description| description.contains("single-tenant")),
            "default project must warn about its permissiveness"
        );
    }

    #[test]
    fn permissive_policy_stub_allows_every_check() {
        let policy = PermissivePolicy;
        assert!(policy.allows_source_repo("https://github.com/example/payments.git"));
        assert!(policy.allows_source_repo("file:///tmp/repo"));
        assert!(policy.allows_destination(&ProjectDestination {
            cluster: "prod-west".to_owned(),
            namespace: "payments".to_owned(),
        }));
        assert!(
            policy.allows_cluster_resource(&GroupKind::new(
                "rbac.authorization.k8s.io",
                "ClusterRole"
            ))
        );
        assert!(policy.allows_namespace_resource(&GroupKind::new("", "Secret")));
        assert!(policy.allows_service_account("payments", "payments-sa"));
        assert!(policy.allows_source_namespace("any-namespace"));
    }
}
