//! `Application` custom resource: the user-facing declaration of a GitOps workload.
//!
//! The schema is deliberately built so invalid states are unrepresentable:
//! [`SyncPolicy::automated`] is an `Option`, therefore `automated: false` combined with
//! `selfHeal: true` cannot be expressed at all (review finding P1-06 / trap M5-class bug).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::DEFAULT_PROJECT_NAME;
use crate::status::ApplicationStatus;

/// Revision used when `spec.source.git.targetRevision` is omitted (matches Argo CD).
pub const DEFAULT_TARGET_REVISION: &str = "HEAD";

/// Destination cluster used when `spec.destination.cluster` is omitted.
pub const DEFAULT_DESTINATION_CLUSTER: &str = "in-cluster";

/// Default reconcile requeue interval in seconds when `spec.requeueAfterSeconds` is omitted.
pub const DEFAULT_REQUEUE_AFTER_SECONDS: u32 = 180;

/// Lowest accepted `spec.revisionHistoryLimit`.
pub const MIN_REVISION_HISTORY_LIMIT: i32 = 1;

/// Highest accepted `spec.revisionHistoryLimit` (keeps `status.history` bounded).
pub const MAX_REVISION_HISTORY_LIMIT: i32 = 20;

/// Default `spec.revisionHistoryLimit` when omitted.
pub const DEFAULT_REVISION_HISTORY_LIMIT: i32 = 10;

/// Default `spec.syncPolicy.retry.limit`.
pub const DEFAULT_RETRY_LIMIT: u32 = 5;

/// Default initial retry backoff duration in seconds.
pub const DEFAULT_RETRY_BACKOFF_DURATION_SECONDS: u32 = 5;

/// Default retry backoff factor.
pub const DEFAULT_RETRY_BACKOFF_FACTOR: u32 = 2;

/// Default maximum retry backoff duration in seconds.
pub const DEFAULT_RETRY_BACKOFF_MAX_DURATION_SECONDS: u32 = 180;

/// `Application` custom resource (`ferriscd.io/v1alpha1`).
///
/// The generated `CustomResourceDefinition` carries the `status` subresource plus the
/// `SYNC` / `HEALTH` / `REVISION` / `AGE` printer columns.
// `kube` takes one `printcolumn(...)` attribute per column, so repeated keys such as
// `type_ = "string"` are intentional and must not be de-duplicated.
#[allow(clippy::duplicated_attributes)]
#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[kube(
    group = "ferriscd.io",
    version = "v1alpha1",
    kind = "Application",
    namespaced,
    status = "ApplicationStatus",
    shortname = "app",
    shortname = "apps",
    doc = "Declarative GitOps application: render a Git source and sync it to a destination cluster namespace",
    derive = "PartialEq",
    printcolumn(
        name = "SYNC",
        type_ = "string",
        json_path = ".status.sync.status",
        description = "Current sync status (Synced, OutOfSync, Unknown)"
    ),
    printcolumn(
        name = "HEALTH",
        type_ = "string",
        json_path = ".status.health.status",
        description = "Aggregated health of the managed resources"
    ),
    printcolumn(
        name = "REVISION",
        type_ = "string",
        json_path = ".status.sync.revision",
        description = "Git revision currently deployed"
    ),
    printcolumn(
        name = "AGE",
        type_ = "date",
        json_path = ".metadata.creationTimestamp",
        description = "Age of the Application"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSpec {
    /// `AppProject` this application belongs to; checked on every rendered resource.
    ///
    /// Defaults to [`DEFAULT_PROJECT_NAME`].
    #[serde(default = "default_project")]
    pub project: String,

    /// ServiceAccount (in the destination namespace) used for impersonation.
    ///
    /// Only honored when the referenced `AppProject` lists it in `allowedServiceAccounts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account_name: Option<String>,

    /// Where the desired manifests come from and how they are rendered.
    pub source: SourceSpec,

    /// Target cluster and namespace.
    pub destination: DestinationSpec,

    /// Automated sync policy, sync options, and retry behaviour.
    ///
    /// Omitted entirely for manual-only sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_policy: Option<SyncPolicy>,

    /// Field-level drift suppressions applied before diffing.
    #[serde(default)]
    pub ignore_differences: Vec<IgnoreDifference>,

    /// Periodic reconcile interval in seconds (default [`DEFAULT_REQUEUE_AFTER_SECONDS`]).
    #[serde(default = "default_requeue_after_seconds")]
    #[schemars(range(min = 1, max = 86_400))]
    pub requeue_after_seconds: u32,

    /// Hard cap on `status.history` entries, validated to `1..=20`
    /// (default [`DEFAULT_REVISION_HISTORY_LIMIT`]).
    #[serde(default = "default_revision_history_limit")]
    #[schemars(range(min = 1, max = 20))]
    pub revision_history_limit: i32,
}

fn default_project() -> String {
    DEFAULT_PROJECT_NAME.to_owned()
}

fn default_requeue_after_seconds() -> u32 {
    DEFAULT_REQUEUE_AFTER_SECONDS
}

fn default_revision_history_limit() -> i32 {
    DEFAULT_REVISION_HISTORY_LIMIT
}

/// Source of the desired state: exactly one Git repository plus its renderer.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceSpec {
    /// Git repository, revision, and manifest sub-path.
    pub git: GitSourceSpec,

    /// Renderer used to turn the checked-out path into Kubernetes manifests.
    #[serde(default)]
    pub renderer: RendererSpec,
}

/// Git repository coordinates for an [`Application`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitSourceSpec {
    /// Repository clone URL (`https://`, `ssh://`, SCP-style SSH, or a local test path).
    #[serde(rename = "repoURL")]
    pub repo_url: String,

    /// Branch, tag, `HEAD`, or full 40-character commit SHA.
    #[serde(default = "default_target_revision")]
    pub target_revision: String,

    /// Relative sub-directory inside the repository (`""` means repository root).
    #[serde(default)]
    pub path: String,
}

fn default_target_revision() -> String {
    DEFAULT_TARGET_REVISION.to_owned()
}

/// Manifest renderer selection.
///
/// Exactly one renderer is representable, so a source can never request both
/// `plainYaml` and `helm`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum RendererSpec {
    /// Automatic renderer detection based on the files present in the source path.
    Auto(AutoRenderer),
    /// Literal multi-document YAML/JSON manifests.
    PlainYaml(PlainYamlRenderer),
    /// Kustomize overlay (remote resources are rejected).
    Kustomize(KustomizeRenderer),
    /// Helm chart rendering (CRDs are not installed unless `includeCRDs` is set).
    Helm(HelmRenderer),
}

impl Default for RendererSpec {
    fn default() -> Self {
        Self::Auto(AutoRenderer {})
    }
}

/// Automatic renderer detection (empty marker object: `renderer: {auto: {}}`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct AutoRenderer {}

/// Plain YAML/JSON manifest renderer.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct PlainYamlRenderer {
    /// Recurse into sub-directories of `spec.source.git.path` (default `true`).
    #[serde(default = "default_true")]
    pub recursive: bool,
}

/// Kustomize renderer.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct KustomizeRenderer {
    /// Overlay directory (relative to `spec.source.git.path`); defaults to the source path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kustomization_path: Option<String>,

    /// Image overrides applied to the rendered output (`name=newImage:tag`).
    #[serde(default)]
    pub images: Vec<String>,
}

/// Helm renderer.
///
/// Deliberately minimal for `v1alpha1`: arbitrary chart value maps are added with the
/// Helm integration (Phase 11) instead of leaking an untyped schema into the CRD now.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct HelmRenderer {
    /// Release name used for rendering; defaults to the `Application` name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_name: Option<String>,

    /// Additional values files, relative to `spec.source.git.path`.
    #[serde(default)]
    pub value_files: Vec<String>,

    /// Install CRDs shipped in the chart's `crds/` directory (default `false`).
    #[serde(default, rename = "includeCRDs")]
    pub include_crds: bool,
}

/// Target cluster and namespace for rendered resources.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DestinationSpec {
    /// Target cluster: `in-cluster` or a FerrisCD cluster Secret name.
    #[serde(default = "default_destination_cluster")]
    pub cluster: String,

    /// Namespace injected onto namespaced resources that do not set one explicitly.
    pub namespace: String,
}

fn default_destination_cluster() -> String {
    DEFAULT_DESTINATION_CLUSTER.to_owned()
}

/// Sync policy: automation, per-sync options, and retry behaviour.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncPolicy {
    /// Automated sync policy.
    ///
    /// `None` means manual-only sync. Because this is an `Option` of a struct, the
    /// invalid combination `automated: false` + `selfHeal: true` cannot be expressed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub automated: Option<AutomatedSyncPolicy>,

    /// Sync options applied to every sync (safe defaults: no forced apply, no CRD/namespace pruning).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_options: Option<SyncOptions>,

    /// Bounded retry policy for failed sync operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryPolicy>,
}

impl SyncPolicy {
    /// Returns whether automated sync is enabled.
    #[must_use]
    pub fn is_automated(&self) -> bool {
        self.automated.is_some()
    }

    /// Returns whether automated self-healing (drift correction) is enabled.
    ///
    /// Always `false` when [`Self::automated`] is `None`.
    #[must_use]
    pub fn self_heal_enabled(&self) -> bool {
        self.automated
            .as_ref()
            .is_some_and(|automated| automated.self_heal)
    }

    /// Returns whether automated pruning of removed resources is enabled.
    #[must_use]
    pub fn prune_enabled(&self) -> bool {
        self.automated
            .as_ref()
            .is_some_and(|automated| automated.prune)
    }
}

/// Automated sync policy.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct AutomatedSyncPolicy {
    /// Prune resources removed from Git (never CRDs/Namespaces unless explicitly opted in).
    #[serde(default)]
    pub prune: bool,

    /// Re-apply live drift automatically.
    #[serde(default)]
    pub self_heal: bool,
}

/// Per-sync behaviour flags.
///
/// Safety defaults: `pruneCRDs`/`pruneNamespaces`/`serverSideForce` are `false`, so a
/// misconfigured `Application` can never clobber HPA-managed fields or delete cluster
/// infrastructure.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct SyncOptions {
    /// Create `spec.destination.namespace` when it does not exist.
    pub create_namespace: bool,

    /// Apply pruning last, after every other resource converged.
    pub prune_last: bool,

    /// Allow pruning `CustomResourceDefinition` objects (safety rail: default `false`).
    #[serde(rename = "pruneCRDs")]
    pub prune_crds: bool,

    /// Allow pruning `Namespace` objects (safety rail: default `false`).
    #[serde(rename = "pruneNamespaces")]
    pub prune_namespaces: bool,

    /// Send `force: true` in Server-Side Apply patches (default `false`).
    pub server_side_force: bool,

    /// Only apply resources that are actually out of sync (default `true`).
    pub apply_out_of_sync_only: bool,

    /// Field managers whose ownership FerrisCD may take over (brownfield adoption).
    pub takeover_field_managers: Vec<String>,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            create_namespace: false,
            prune_last: true,
            prune_crds: false,
            prune_namespaces: false,
            server_side_force: false,
            apply_out_of_sync_only: true,
            takeover_field_managers: Vec::new(),
        }
    }
}

/// Field-level drift suppression for one Group/Kind (optionally narrowed by name/namespace).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct IgnoreDifference {
    /// API group (`""` for the core group); omitted means "any group".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Kind the suppression applies to.
    pub kind: String,

    /// Resource name the suppression applies to; omitted means "any name".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Resource namespace the suppression applies to; omitted means "any namespace".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// RFC 6901 JSON Pointers whose live/desired values are ignored during diffing.
    #[serde(default)]
    pub json_pointers: Vec<String>,

    /// Field managers whose owned fields are ignored during diffing.
    #[serde(default)]
    pub managed_fields_managers: Vec<String>,
}

/// Bounded retry policy for sync operations.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (default [`DEFAULT_RETRY_LIMIT`]).
    #[serde(default = "default_retry_limit")]
    pub limit: u32,

    /// Exponential backoff parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backoff: Option<RetryBackoff>,
}

fn default_retry_limit() -> u32 {
    DEFAULT_RETRY_LIMIT
}

/// Exponential backoff parameters for sync retries.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct RetryBackoff {
    /// Initial backoff duration in seconds.
    pub duration_seconds: u32,

    /// Multiplier applied after every failed attempt.
    pub factor: u32,

    /// Upper bound for a single backoff duration in seconds.
    pub max_duration_seconds: u32,
}

impl Default for RetryBackoff {
    fn default() -> Self {
        Self {
            duration_seconds: DEFAULT_RETRY_BACKOFF_DURATION_SECONDS,
            factor: DEFAULT_RETRY_BACKOFF_FACTOR,
            max_duration_seconds: DEFAULT_RETRY_BACKOFF_MAX_DURATION_SECONDS,
        }
    }
}

/// Validation failure for an [`ApplicationSpec`].
///
/// The generated CRD schema rejects the same violations server-side (422); this type
/// gives the controller and CLI an offline, equally strict check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecValidationError {
    /// `spec.project` was empty.
    #[error("spec.project must not be empty")]
    EmptyProject,
    /// `spec.destination.namespace` was empty.
    #[error("spec.destination.namespace must not be empty")]
    EmptyDestinationNamespace,
    /// `spec.source.git.repoURL` was empty.
    #[error("spec.source.git.repoURL must not be empty")]
    EmptyRepoUrl,
    /// `spec.source.git.targetRevision` was empty.
    #[error("spec.source.git.targetRevision must not be empty")]
    EmptyTargetRevision,
    /// `spec.requeueAfterSeconds` was zero.
    #[error("spec.requeueAfterSeconds must be greater than zero")]
    ZeroRequeueAfter,
    /// `spec.revisionHistoryLimit` was outside `1..=20`.
    #[error("spec.revisionHistoryLimit must be between 1 and 20, got {value}")]
    RevisionHistoryLimitOutOfRange {
        /// The rejected value.
        value: i32,
    },
}

impl ApplicationSpec {
    /// Validates the spec against the invariants the CRD schema enforces.
    ///
    /// This mirrors the OpenAPI `minimum`/`maximum` bounds so a spec is rejected
    /// identically offline (CLI/controller) and online (API server 422).
    pub fn validate(&self) -> Result<(), SpecValidationError> {
        if self.project.trim().is_empty() {
            return Err(SpecValidationError::EmptyProject);
        }
        if self.destination.namespace.trim().is_empty() {
            return Err(SpecValidationError::EmptyDestinationNamespace);
        }
        if self.source.git.repo_url.trim().is_empty() {
            return Err(SpecValidationError::EmptyRepoUrl);
        }
        if self.source.git.target_revision.trim().is_empty() {
            return Err(SpecValidationError::EmptyTargetRevision);
        }
        if self.requeue_after_seconds == 0 {
            return Err(SpecValidationError::ZeroRequeueAfter);
        }
        if !(MIN_REVISION_HISTORY_LIMIT..=MAX_REVISION_HISTORY_LIMIT)
            .contains(&self.revision_history_limit)
        {
            return Err(SpecValidationError::RevisionHistoryLimitOutOfRange {
                value: self.revision_history_limit,
            });
        }
        Ok(())
    }

    /// Returns the effective sync options (`SyncOptions::default()` when unspecified).
    #[must_use]
    pub fn sync_options(&self) -> SyncOptions {
        self.sync_policy
            .as_ref()
            .and_then(|policy| policy.sync_options.clone())
            .unwrap_or_default()
    }
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    const MINIMAL_APPLICATION: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: payment-service
  namespace: ferriscd-system
spec:
  source:
    git:
      repoURL: https://github.com/example/payment-service.git
  destination:
    namespace: payments
"#;

    const FULL_APPLICATION: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: payment-service
  namespace: ferriscd-system
spec:
  project: payments
  serviceAccountName: payments-sa
  source:
    git:
      repoURL: https://github.com/example/payment-service.git
      targetRevision: main
      path: deploy/production
    renderer:
      kustomize:
        kustomizationPath: overlays/prod
        images:
          - payment-api=ghcr.io/example/payment-api:v2
  destination:
    cluster: in-cluster
    namespace: payments
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      createNamespace: true
      pruneLast: true
      pruneCRDs: false
      pruneNamespaces: false
      serverSideForce: false
      applyOutOfSyncOnly: true
      takeoverFieldManagers:
        - kubectl-client-side-apply
    retry:
      limit: 3
      backoff:
        durationSeconds: 5
        factor: 2
        maxDurationSeconds: 120
  ignoreDifferences:
    - group: apps
      kind: Deployment
      jsonPointers:
        - /spec/replicas
  requeueAfterSeconds: 60
  revisionHistoryLimit: 20
"#;

    fn parse(yaml: &str) -> Application {
        serde_saphyr::from_str(yaml).expect("application yaml must parse")
    }

    #[test]
    fn application_yaml_round_trips_with_camel_case_field_names() {
        let app = parse(FULL_APPLICATION);
        assert_eq!(app.spec.project, "payments");
        assert_eq!(
            app.spec.service_account_name.as_deref(),
            Some("payments-sa")
        );
        assert_eq!(
            app.spec.source.git.repo_url,
            "https://github.com/example/payment-service.git"
        );
        assert_eq!(app.spec.source.git.target_revision, "main");
        assert_eq!(app.spec.revision_history_limit, 20);

        let serialized = serde_saphyr::to_string(&app).expect("application must serialize");
        let rehydrated = parse(&serialized);
        assert_eq!(rehydrated, app);

        let value: Value = serde_json::to_value(&app).expect("application must serialize to json");
        let spec = &value["spec"];
        assert_eq!(spec["serviceAccountName"], json!("payments-sa"));
        assert_eq!(spec["requeueAfterSeconds"], json!(60));
        assert_eq!(spec["revisionHistoryLimit"], json!(20));
        assert_eq!(
            spec["ignoreDifferences"][0]["jsonPointers"][0],
            json!("/spec/replicas")
        );
        assert_eq!(spec["syncPolicy"]["automated"]["selfHeal"], json!(true));
        assert_eq!(
            spec["syncPolicy"]["syncOptions"]["takeoverFieldManagers"][0],
            json!("kubectl-client-side-apply")
        );
        assert_eq!(
            spec["source"]["git"]["repoURL"],
            json!("https://github.com/example/payment-service.git")
        );
        // snake_case keys must never leak onto the wire.
        assert!(spec.get("service_account_name").is_none());
        assert!(spec.get("revision_history_limit").is_none());
    }

    #[test]
    fn defaults_are_applied_for_omitted_fields() {
        let app = parse(MINIMAL_APPLICATION);
        let spec = &app.spec;
        assert_eq!(spec.project, DEFAULT_PROJECT_NAME);
        assert_eq!(spec.requeue_after_seconds, 180);
        assert_eq!(spec.revision_history_limit, 10);
        assert_eq!(spec.source.git.target_revision, DEFAULT_TARGET_REVISION);
        assert_eq!(spec.source.git.path, "");
        assert_eq!(spec.source.renderer, RendererSpec::Auto(AutoRenderer {}));
        assert_eq!(spec.destination.cluster, DEFAULT_DESTINATION_CLUSTER);
        assert!(spec.sync_policy.is_none());
        assert!(spec.ignore_differences.is_empty());
        assert!(spec.validate().is_ok());

        // Manual-only sync: no automation, no self-heal, no pruning.
        let policy = SyncPolicy::default();
        assert!(!policy.is_automated());
        assert!(!policy.self_heal_enabled());
        assert!(!policy.prune_enabled());

        // Sync option safety rails.
        let options = spec.sync_options();
        assert!(!options.server_side_force);
        assert!(!options.prune_crds);
        assert!(!options.prune_namespaces);
        assert!(options.apply_out_of_sync_only);
        assert!(options.prune_last);
    }

    #[test]
    fn partial_sync_options_keep_safety_defaults_and_wire_names() {
        // Only one option is set; every other option must fall back to its safe default
        // rather than to `false`, so a half-written syncOptions block cannot enable
        // forced applies or CRD pruning.
        let app = parse(&MINIMAL_APPLICATION.replace(
            "  destination:",
            "  syncPolicy:\n    syncOptions:\n      createNamespace: true\n  destination:",
        ));
        let options = app.spec.sync_options();
        assert!(options.create_namespace);
        assert!(options.prune_last);
        assert!(options.apply_out_of_sync_only);
        assert!(!options.prune_crds);
        assert!(!options.prune_namespaces);
        assert!(!options.server_side_force);
        assert!(options.takeover_field_managers.is_empty());

        // Acronym-bearing fields must keep their Kubernetes spelling on the wire.
        let value = serde_json::to_value(SyncOptions::default()).expect("options must serialize");
        for expected in [
            "createNamespace",
            "pruneLast",
            "pruneCRDs",
            "pruneNamespaces",
            "serverSideForce",
            "applyOutOfSyncOnly",
            "takeoverFieldManagers",
        ] {
            assert!(
                value.get(expected).is_some(),
                "serialized syncOptions is missing {expected}: {value}"
            );
        }
        assert!(value.get("prune_crds").is_none());
        assert!(value.get("prune_namespaces").is_none());
    }

    #[test]
    fn automated_sync_policy_cannot_be_false() {
        // `automated: false` (or a bare boolean) is not expressible: the field is an
        // optional struct, so the invalid `automated: false, selfHeal: true` state is
        // impossible to write instead of being silently accepted (Finding P1-06).
        let with_false_automated = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: broken
spec:
  source:
    git:
      repoURL: https://github.com/example/repo.git
  destination:
    namespace: payments
  syncPolicy:
    automated: false
    selfHeal: true
"#;
        let err = serde_saphyr::from_str::<Application>(with_false_automated)
            .expect_err("`automated: false` must not deserialize");
        let message = err.to_string();
        assert!(
            message.contains("automated") || message.contains("invalid type"),
            "unexpected error message: {message}"
        );

        // A struct form is the only way to enable automation, and self-heal tracks it.
        let with_policy = parse(&MINIMAL_APPLICATION.replace(
            "  destination:",
            "  syncPolicy:\n    automated:\n      selfHeal: true\n  destination:",
        ));
        let policy = with_policy.spec.sync_policy.expect("syncPolicy present");
        assert!(policy.is_automated());
        assert!(policy.self_heal_enabled());
        assert!(!policy.prune_enabled());
    }

    #[test]
    fn revision_history_limit_is_validated_to_bounds() {
        for accepted in [MIN_REVISION_HISTORY_LIMIT, MAX_REVISION_HISTORY_LIMIT] {
            let yaml = MINIMAL_APPLICATION.replace(
                "  destination:",
                &format!("  revisionHistoryLimit: {accepted}\n  destination:"),
            );
            let app = parse(&yaml);
            assert_eq!(app.spec.revision_history_limit, accepted);
            assert!(app.spec.validate().is_ok());
        }

        for rejected in [0, MAX_REVISION_HISTORY_LIMIT + 1, -1] {
            let yaml = MINIMAL_APPLICATION.replace(
                "  destination:",
                &format!("  revisionHistoryLimit: {rejected}\n  destination:"),
            );
            let app = parse(&yaml);
            assert_eq!(
                app.spec.validate(),
                Err(SpecValidationError::RevisionHistoryLimitOutOfRange { value: rejected })
            );
        }
    }

    #[test]
    fn validate_rejects_empty_required_values() {
        let mut spec = parse(MINIMAL_APPLICATION).spec;
        assert!(spec.validate().is_ok());

        let mut empty_project = spec.clone();
        empty_project.project = "  ".to_owned();
        assert_eq!(
            empty_project.validate(),
            Err(SpecValidationError::EmptyProject)
        );

        let mut empty_ns = spec.clone();
        empty_ns.destination.namespace.clear();
        assert_eq!(
            empty_ns.validate(),
            Err(SpecValidationError::EmptyDestinationNamespace)
        );

        let mut empty_url = spec.clone();
        empty_url.source.git.repo_url.clear();
        assert_eq!(empty_url.validate(), Err(SpecValidationError::EmptyRepoUrl));

        let mut empty_revision = spec.clone();
        empty_revision.source.git.target_revision.clear();
        assert_eq!(
            empty_revision.validate(),
            Err(SpecValidationError::EmptyTargetRevision)
        );

        spec.requeue_after_seconds = 0;
        assert_eq!(spec.validate(), Err(SpecValidationError::ZeroRequeueAfter));
    }

    #[test]
    fn schema_bounds_revision_history_limit_and_requires_source_fields() {
        let schema = serde_json::to_value(schemars::schema_for!(ApplicationSpec))
            .expect("schema must serialize");
        let limit = &schema["properties"]["revisionHistoryLimit"];
        assert_eq!(limit["minimum"], json!(1));
        assert_eq!(limit["maximum"], json!(20));

        let required = schema["required"]
            .as_array()
            .expect("required must be an array")
            .clone();
        let required: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        assert!(required.contains(&"source"));
        assert!(required.contains(&"destination"));
        assert!(!required.contains(&"project"));
        assert!(!required.contains(&"revisionHistoryLimit"));
    }
}
