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

    /// Pre-sync policy rules enforced on every rendered resource of this project (`T20.2`).
    ///
    /// Additive and optional: a project that lists none behaves exactly as before `T20.2`. Each
    /// rule's `expression` is an invariant that **must hold** — a resource the expression rejects
    /// is a violation. `enforcement: Enforce` refuses the sync before anything is applied or
    /// pruned; `enforcement: Warn` surfaces an advisory condition and lets it proceed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_rules: Vec<PolicyRuleSpec>,
}

/// What a policy rule does when its expression rejects a resource.
#[derive(
    Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, JsonSchema,
)]
pub enum PolicyEnforcement {
    /// Refuse the sync — a terminal pre-sync violation with zero applies and zero prunes.
    ///
    /// The default on purpose: a rule whose `enforcement` was forgotten must block, never wave a
    /// non-compliant manifest through.
    #[default]
    Enforce,

    /// Report an advisory `PolicyAdvisory` condition and let the sync proceed.
    Warn,
}

impl PolicyEnforcement {
    /// Whether this enforcement refuses the sync.
    ///
    /// One typed predicate for every consumer — the engine, `ferriscd app diff`, and the API views —
    /// so no code path compares against the literal `"Enforce"` and a rename (or a third variant)
    /// cannot silently turn a refusal into an advisory.
    #[must_use]
    pub fn is_blocking(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

impl std::fmt::Display for PolicyEnforcement {
    /// The wire label (`Enforce`/`Warn`), so a rendered banner and the JSON always agree.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Enforce => "Enforce",
            Self::Warn => "Warn",
        })
    }
}

/// Which expression engine evaluates a policy rule.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq, JsonSchema)]
pub enum PolicyRuleEngine {
    /// The built-in, offline, bounded CEL subset (the default).
    #[default]
    Cel,

    /// Embedded OPA/Rego. Requires a controller **binary built** with the `opa-policy` feature
    /// (`cargo build -p ferriscd-cli --features opa-policy`, or the image's `FERRISCD_FEATURES`
    /// build arg — see `deploy/README.md`); without it the rule fails closed as a compile error
    /// instead of being skipped. It is a build-time choice, not a runtime flag.
    Rego,
}

/// One pre-sync policy rule (`T20.2`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRuleSpec {
    /// Rule name; appears verbatim in every violation message and in `status.conditions`.
    pub name: String,

    /// `Enforce` (default) or `Warn`.
    #[serde(default)]
    pub enforcement: PolicyEnforcement,

    /// Expression engine; unset means [`PolicyRuleEngine::Cel`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<PolicyRuleEngine>,

    /// GroupKind globs the rule applies to (`*`, `Kind`, `group/Kind`, `group/*`).
    ///
    /// Empty means "every rendered resource"; a hook is a rendered resource too. A manifest-shaped
    /// `v1/Secret` is normalized to `Secret`, but an entry that names only an `apiVersion`
    /// (`v1`, `apps/v1`) is **refused** by the policy gate: it would match no resource at all, and a
    /// rule that matches nothing allows everything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_kinds: Vec<String>,

    /// The invariant that must hold for every matching resource.
    ///
    /// A `false` result is a violation, the Kubernetes `x-kubernetes-validations` convention: write
    /// `!object.spec.template.spec.containers.exists(c, has(c.securityContext) &&
    /// c.securityContext.privileged == true)` to forbid privileged containers.
    pub expression: String,

    /// Operator-facing violation text; a generated sentence naming the rule is used when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
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

    /// `T20.2`: `policyRules` is additive, defaults to `Enforce`, and survives a round-trip.
    #[test]
    fn policy_rules_round_trip_with_enforce_as_the_safe_default() {
        let project = parse(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  sourceRepos: ["*"]
  destinations:
    - cluster: in-cluster
      namespace: payments
  policyRules:
    - name: no-privileged
      matchKinds: ["Pod", "apps/*"]
      expression: "!object.spec.containers.exists(c, c.securityContext.privileged == true)"
      message: privileged containers are forbidden
    - name: prefer-registry
      enforcement: Warn
      engine: Rego
      expression: "package ferriscd\nallow = true"
"#,
        );
        let rules = &project.spec.policy_rules;
        assert_eq!(rules.len(), 2);

        // An omitted `enforcement` is `Enforce`: a rule whose author forgot the field must block.
        assert_eq!(rules[0].name, "no-privileged");
        assert_eq!(rules[0].enforcement, PolicyEnforcement::Enforce);
        assert_eq!(rules[0].engine, None, "unset engine means CEL");
        assert_eq!(
            rules[0].match_kinds,
            vec!["Pod".to_owned(), "apps/*".to_owned()]
        );
        assert_eq!(
            rules[0].message.as_deref(),
            Some("privileged containers are forbidden")
        );

        assert_eq!(rules[1].enforcement, PolicyEnforcement::Warn);
        assert_eq!(rules[1].engine, Some(PolicyRuleEngine::Rego));

        // Round-trip through YAML and JSON: the wire form is camelCase and stable.
        let yaml = serde_saphyr::to_string(&project).expect("project must serialize");
        assert_eq!(parse(&yaml), project);
        let value: Value = serde_json::to_value(&project).expect("project must serialize to json");
        let wire = &value["spec"]["policyRules"];
        assert_eq!(wire[0]["name"], json!("no-privileged"));
        assert_eq!(wire[0]["enforcement"], json!("Enforce"));
        assert_eq!(wire[0]["matchKinds"][1], json!("apps/*"));
        assert_eq!(wire[1]["engine"], json!("Rego"));
        assert!(wire[0].get("enforcement_").is_none());

        // The schema carries the rules and the enforcement enum, so the CRD (and `kubectl
        // explain`) documents them without a hand-written schema.
        let schema = serde_json::to_value(schemars::schema_for!(AppProjectSpec))
            .expect("schema must serialize");
        assert!(
            schema["properties"]["policyRules"].is_object(),
            "policyRules must be in the generated schema"
        );
        let defs = schema["$defs"].as_object().expect("definitions");
        let enforcement =
            serde_json::to_value(defs["PolicyEnforcement"].clone()).expect("enum schema");
        let variants: Vec<&str> = enforcement["oneOf"]
            .as_array()
            .expect("a string enum schema")
            .iter()
            .filter_map(|variant| variant["const"].as_str())
            .collect();
        assert_eq!(variants, vec!["Enforce", "Warn"]);

        // The `Display` impl (used by the CLI banner and by every message) must never drift from
        // the serde wire form: they are two renderings of the same label.
        for enforcement in [PolicyEnforcement::Enforce, PolicyEnforcement::Warn] {
            let wire = serde_json::to_value(enforcement).expect("unit variant serializes");
            assert_eq!(enforcement.to_string(), wire, "{enforcement:?}");
        }
        assert!(PolicyEnforcement::Enforce.is_blocking());
        assert!(!PolicyEnforcement::Warn.is_blocking());
    }

    /// A rendered `policyRules` entry with no expression is refused by the API server's schema:
    /// `expression` is required, because a rule that says nothing is not a rule.
    #[test]
    fn a_policy_rule_requires_an_expression() {
        let schema = serde_json::to_value(schemars::schema_for!(PolicyRuleSpec))
            .expect("schema must serialize");
        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("required list")
            .iter()
            .filter_map(|entry| entry.as_str())
            .collect();
        assert!(required.contains(&"name"), "{required:?}");
        assert!(required.contains(&"expression"), "{required:?}");
        assert!(
            !required.contains(&"enforcement"),
            "enforcement defaults to Enforce instead of being required"
        );
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
    fn permissive_stub_is_gone_and_the_default_project_is_the_single_tenant_boundary() {
        // The `PermissivePolicy` stub was removed when `T12.1` landed: the `default` project's
        // all-wildcard spec is now the *only* permissive thing, and it is a deliberate, reviewable
        // manifest rather than a compile-time allow-everything type.
        let project: AppProject =
            serde_saphyr::from_str(DEFAULT_PROJECT_MANIFEST).expect("default project must parse");
        let spec = project.spec;
        assert_eq!(spec.source_repos, vec![WILDCARD]);
        assert!(
            spec.destinations
                .iter()
                .all(|destination| destination.namespace == WILDCARD),
            "the default project must advertise its permissiveness explicitly"
        );
        assert_eq!(spec.source_namespaces, vec![CONTROL_PLANE_NAMESPACE]);
    }
}
