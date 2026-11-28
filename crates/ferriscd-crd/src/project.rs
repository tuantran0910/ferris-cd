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
use crate::sync_window::{SyncWindow, SyncWindowParseError};

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

    /// Deployment-governance windows that decide *when* this project may sync (`T17.4`).
    ///
    /// Additive and optional: an `AppProject` that omits `syncWindows` behaves exactly as it did
    /// in `v1.0` (no window, so nothing is blocked), and the field is omitted again on the way out
    /// (`skip_serializing_if`), so a `v1.0` manifest round-trips byte-for-byte. Evaluation and its
    /// deny-over-allow precedence live in `ferriscd_engine::policy::sync_windows`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sync_windows: Vec<SyncWindow>,
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

/// A `syncWindows` entry that cannot be evaluated.
///
/// Every variant is terminal: the operator fixes the `AppProject`, nothing is retried. The index is
/// the position in `spec.syncWindows`, so the message points at one list entry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncWindowSpecError {
    /// `spec.syncWindows[i]` is malformed.
    #[error("spec.syncWindows[{index}]: {source}")]
    Window {
        /// Position in `spec.syncWindows`.
        index: usize,
        /// The parse failure.
        #[source]
        source: SyncWindowParseError,
    },
}

impl SyncWindowSpecError {
    /// Always `false`: a malformed window is a configuration error, not a transient failure.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

/// Failure while validating an [`AppProjectSpec`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProjectValidationError {
    /// A `syncWindows` entry is malformed (`T17.4`).
    #[error("{0}")]
    SyncWindow(#[from] SyncWindowSpecError),
}

impl ProjectValidationError {
    /// Always `false`: validation is deterministic.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

impl AppProjectSpec {
    /// Validates the parts of the spec the OpenAPI schema cannot express (`T17.4`).
    ///
    /// The CRD schema enforces types, but a cron expression, an IANA time zone, and a bounded
    /// duration are all *strings*: without this check a typo would silently become a deny-all
    /// window at runtime. Rejecting it here — in the CLI, in the controller, and in any future
    /// admission path — fails closed at the earliest possible point, and the runtime keeps its own
    /// fail-closed guard for a project that reached the cluster before the typo was found.
    ///
    /// **There is no production caller yet (finding M1).** The `AppProject` CRD has no admission
    /// webhook and the controller does not write `AppProject` specs, so *today* the enforcement
    /// point is the runtime guard: the sync pipeline compiles `spec.syncWindows` on every pass and
    /// denies every sync of a project with an unparseable entry (plus the
    /// `Ready=False/SyncWindowInvalid` condition on the project, so the operator sees why). Only
    /// the tests call this method; **any future path that writes an `AppProject` must call it
    /// before the write**, so a typo is rejected instead of parked in fail-closed state.
    ///
    /// # Errors
    ///
    /// [`ProjectValidationError::SyncWindow`] naming the malformed `spec.syncWindows[i]` entry.
    pub fn validate(&self) -> Result<(), ProjectValidationError> {
        for (index, window) in self.sync_windows.iter().enumerate() {
            window
                .validate()
                .map_err(|source| SyncWindowSpecError::Window { index, source })?;
        }
        Ok(())
    }

    /// Whether any deployment-governance window is configured.
    #[must_use]
    pub fn has_sync_windows(&self) -> bool {
        !self.sync_windows.is_empty()
    }
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

/// Condition reason recorded on an `AppProject` whose `spec.syncWindows` cannot be evaluated
/// (`T17.4`).
///
/// Lives in the CRD, not in the single writer: the controller *sets* the condition and the engine's
/// policy snapshot *reads* it back (finding H-A, so a project whose windows were all removed still
/// gets its stale `Ready=False/SyncWindowInvalid` cleared), and two spellings of the same wire string
/// would silently disagree.
pub const REASON_SYNC_WINDOW_INVALID: &str = "SyncWindowInvalid";

impl AppProjectStatus {
    /// Whether this status currently records the `Ready=False/SyncWindowInvalid` condition.
    ///
    /// The status is read back on the next pass precisely to decide whether the sync pipeline still
    /// owes the project a *clearing* write: once an operator empties `spec.syncWindows`, nothing in
    /// the spec asks for the report any more, so the recorded condition is the only evidence that
    /// there is one to remove (finding H-A).
    #[must_use]
    pub fn records_sync_window_invalid(&self) -> bool {
        self.conditions.iter().any(|condition| {
            condition.type_ == crate::status::CONDITION_READY
                && condition.reason == REASON_SYNC_WINDOW_INVALID
        })
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
        assert!(
            spec.get("syncWindows").is_none(),
            "an empty syncWindows list must be omitted, so a v1.0 manifest round-trips unchanged"
        );
    }

    /// `T17.4`: the additive `syncWindows` field, and the *absence* of it in a `v1.0` fixture.
    ///
    /// The `v1.0` manifest below is exactly what operators apply today (the shipped
    /// `default-project.yaml` plus the full example above). It must deserialize, re-serialize, and
    /// hash to the same spec it did before the field existed — `syncWindows` is `default`ed in and
    /// skipped on the way out.
    #[test]
    fn v1_0_appproject_yaml_fixtures_deserialize_identically() {
        for fixture in [FULL_PROJECT, DEFAULT_PROJECT_MANIFEST] {
            let project = parse(fixture);
            assert!(
                project.spec.sync_windows.is_empty(),
                "a v1.0 AppProject must keep an empty syncWindows list"
            );
            assert!(!project.spec.has_sync_windows());

            // Field-for-field round-trip through YAML and JSON: the additive field changes nothing.
            let yaml = serde_saphyr::to_string(&project).expect("project must serialize");
            assert_eq!(parse(&yaml), project);
            let value: Value = serde_json::to_value(&project).expect("project must serialize");
            assert!(
                value["spec"].get("syncWindows").is_none(),
                "syncWindows must never be emitted for a project that does not use it"
            );
            // The spec validates (no windows is trivially valid) and the fixture is unchanged by
            // the `T17.4` addition: `spec.validate()` only ever inspects `syncWindows`.
            assert_eq!(project.spec.validate(), Ok(()));
        }

        // The committed `v1.0` default project still produces the same JSON document it did before
        // `syncWindows` existed: a golden hash would be brittle, an exact key set is not.
        let project = parse(DEFAULT_PROJECT_MANIFEST);
        let value: Value = serde_json::to_value(&project.spec).expect("spec to json");
        let keys: Vec<&String> = value
            .as_object()
            .expect("spec is an object")
            .keys()
            .filter(|key| key.as_str() != "syncWindows")
            .collect();
        assert_eq!(
            keys,
            vec![
                "allowedServiceAccounts",
                "clusterResourceWhitelist",
                "description",
                "destinations",
                "namespaceResourceBlacklist",
                "namespaceResourceWhitelist",
                "sourceNamespaces",
                "sourceRepos",
            ],
            "the v1.0 field set must stay exactly as it was"
        );
    }

    /// `T17.4`: a project that *does* use windows round-trips, and its defaults are the safe ones.
    #[test]
    fn sync_windows_round_trip_and_default_to_no_manual_override() {
        let project = parse(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: governed
  namespace: ferriscd-system
spec:
  sourceRepos: ["*"]
  destinations:
    - cluster: in-cluster
      namespace: "*"
  syncWindows:
    - kind: deny
      schedule: "0 9-17 * * MON-FRI"
      duration: 8h
      timeZone: America/New_York
      applications: ["payments-*"]
      namespaces: [payments]
      clusters: [prod-*]
      manualSync: false
    - kind: allow
      schedule: "0 2 * * SAT"
      duration: 2h
"#,
        );
        let spec = &project.spec;
        assert_eq!(spec.sync_windows.len(), 2);
        assert_eq!(spec.validate(), Ok(()));

        let deny = &spec.sync_windows[0];
        assert_eq!(deny.kind, crate::sync_window::SyncWindowKind::Deny);
        assert_eq!(deny.time_zone_name(), "America/New_York");
        assert_eq!(deny.applications, vec!["payments-*"]);
        assert!(!deny.manual_sync);

        // Omitted fields take the safe defaults: no filter means "every application", and no
        // `manualSync` means "manual sync does not override the window".
        let allow = &spec.sync_windows[1];
        assert_eq!(allow.kind, crate::sync_window::SyncWindowKind::Allow);
        assert!(allow.applications.is_empty());
        assert!(allow.namespaces.is_empty());
        assert!(allow.clusters.is_empty());
        assert!(!allow.manual_sync);
        assert_eq!(allow.time_zone_name(), "UTC");
        assert!(allow.time_zone.is_none());

        // YAML and JSON round-trip with the camelCase wire names, and `syncWindows` is emitted.
        let yaml = serde_saphyr::to_string(&project).expect("project must serialize");
        assert_eq!(parse(&yaml), project);
        let value: Value = serde_json::to_value(&project).expect("project must serialize");
        assert_eq!(value["spec"]["syncWindows"][0]["kind"], json!("deny"));
        assert_eq!(
            value["spec"]["syncWindows"][0]["timeZone"],
            json!("America/New_York")
        );
        assert_eq!(value["spec"]["syncWindows"][0]["manualSync"], json!(false));
        assert_eq!(value["spec"]["syncWindows"][1]["kind"], json!("allow"));
        assert!(
            value["spec"]["syncWindows"][1].get("timeZone").is_none(),
            "an absent timeZone must not be serialized"
        );

        let schema = serde_json::to_value(schemars::schema_for!(AppProjectSpec))
            .expect("schema must serialize");
        let windows = &schema["properties"]["syncWindows"];
        assert_eq!(windows["type"], json!("array"), "{windows}");
        let window = &schema["$defs"]["SyncWindow"]["properties"];
        for expected in [
            "kind",
            "schedule",
            "duration",
            "timeZone",
            "applications",
            "namespaces",
            "clusters",
            "manualSync",
        ] {
            assert!(
                window.get(expected).is_some(),
                "the SyncWindow schema is missing {expected}"
            );
        }
        // The `kind` enum reaches the CRD schema (kube copies it verbatim), so an API server
        // rejects `kind: maybe` before any controller sees it.
        let kind_schema = schema["$defs"]["SyncWindowKind"].to_string();
        assert!(
            kind_schema.contains("\"allow\"") && kind_schema.contains("\"deny\""),
            "the kind enum must reach the CRD schema: {kind_schema}"
        );
    }

    /// `T17.4` fail-closed validation: a typo in a window is a *spec* error, not a runtime surprise.
    #[test]
    fn project_validation_rejects_malformed_sync_windows() {
        let mut project = parse(
            r#"
apiVersion: ferriscd.io/v1alpha1
kind: AppProject
metadata:
  name: governed
spec:
  syncWindows:
    - kind: deny
      schedule: "0 9 * * MON-FRI"
      duration: 2h
"#,
        );
        assert_eq!(project.spec.validate(), Ok(()));

        let cases: [(&str, &str); 5] = [
            ("0 9 * * MONDAY", "schedule"),
            ("* * * *", "5 fields"),
            ("0 9 * * MON-FRI", "duration"),
            ("0 9 * * MON-FRI", "timeZone"),
            ("0 9 * * MON-FRI", "duration"),
        ];
        let mutations: [fn(&mut crate::sync_window::SyncWindow); 5] = [
            |window| window.schedule = "0 9 * * MONDAY".to_owned(),
            |window| window.schedule = "* * * *".to_owned(),
            |window| window.duration = "8 days".to_owned(),
            |window| window.time_zone = Some("Mars/Olympus".to_owned()),
            |window| window.duration = "14d".to_owned(),
        ];
        for ((expected, needle), mutate) in cases.into_iter().zip(mutations) {
            let original = project.clone();
            if let Some(window) = project.spec.sync_windows.first_mut() {
                mutate(window);
            }
            let err = project
                .spec
                .validate()
                .expect_err("a malformed window must be rejected");
            assert!(!err.is_retryable());
            let message = err.to_string();
            assert!(
                message.contains("spec.syncWindows[0]"),
                "the message must name the entry: {message}"
            );
            assert!(
                message.contains(expected) || message.contains(needle),
                "the message must name the offending field ({expected}): {message}"
            );
            project = original;
        }
        assert_eq!(project.spec.validate(), Ok(()));
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
        assert!(project.spec.sync_windows.is_empty());
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
            "syncWindows",
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
