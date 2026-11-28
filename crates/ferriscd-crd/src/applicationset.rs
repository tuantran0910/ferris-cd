//! `ApplicationSet` custom resource: declarative fleet generation of `Application`s (`T19.3`).
//!
//! The type is **additive**: `Application` stays a single-source, single-destination primitive,
//! and an `ApplicationSet` is only a template plus one generator that produces the parameter sets
//! rendering it. Every generated `Application` is an ordinary `Application` in the
//! `ApplicationSet`'s own namespace, so it passes through the exact same `ApplicationScope`,
//! `AppProjectPolicy`, and impersonation checks as a hand-authored one (design
//! `docs/design/post-v1-backlog.md` §5.1).
//!
//! Two decisions are encoded in the types rather than left to the controller:
//!
//! * **No Turing-complete templating.** The template is a typed [`ApplicationSpec`] plus a name,
//!   labels, and annotations; the engine substitutes flat `{{key}}` placeholders into its string
//!   fields only. There is no loop, function, or expression syntax to abuse, and an unknown key is
//!   an error rather than an empty string.
//! * **Safe fan-out.** [`MAX_GENERATED_APPLICATIONS`] is the absolute ceiling, and
//!   `spec.maxGeneratedApplications` may only *lower* the effective cap.
//! * **Non-destructive deletion default.** [`ApplicationSetSyncPolicy::preserve_resources_on_deletion`]
//!   defaults to `true` (mirroring the `Application` finding C5 posture), and pruning of
//!   no-longer-generated `Application`s is opt-in (`prune: false` by default).

use std::collections::BTreeMap;

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::application::{ApplicationSpec, DEFAULT_REQUEUE_AFTER_SECONDS, DEFAULT_TARGET_REVISION};
use crate::status::{Condition, ConditionStatus};

/// Absolute ceiling on the number of `Application`s one `ApplicationSet` may generate.
///
/// A matrix over two generators is a multiplication, so a typo in a `git.directories` glob plus a
/// broad cluster selector can otherwise try to create thousands of `Application`s in one pass. The
/// engine refuses an expansion over the effective cap (`Ready=False`) instead of truncating it, and
/// `spec.maxGeneratedApplications` may only lower this value.
pub const MAX_GENERATED_APPLICATIONS: i64 = 200;

/// Lowest accepted `spec.maxGeneratedApplications`.
pub const MIN_GENERATED_APPLICATIONS: i64 = 1;

/// Default `spec.requeueAfterSeconds`.
pub const DEFAULT_APPLICATIONSET_REQUEUE_AFTER_SECONDS: u32 = DEFAULT_REQUEUE_AFTER_SECONDS;

/// Label stamped on every generated `Application` (`ferriscd.io/applicationset: <name>`).
pub const APPLICATIONSET_LABEL: &str = "ferriscd.io/applicationset";

/// Finalizer the controller adds to an `ApplicationSet` it manages.
///
/// The finalizer exists for one reason: Kubernetes garbage collection would otherwise delete every
/// generated `Application` (through `metadata.ownerReferences`) the moment the `ApplicationSet` is
/// deleted, which contradicts the non-destructive default. With
/// `preserveResourcesOnDeletion: true` the controller **orphans** the generated `Application`s
/// (drops its owner reference, keeping the object and its workloads) before releasing it.
pub const APPLICATIONSET_FINALIZER: &str = "ferriscd.io/applicationset-cleanup";

/// `ApplicationSet` custom resource (`ferriscd.io/v1alpha1`).
#[derive(CustomResource, Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[kube(
    group = "ferriscd.io",
    version = "v1alpha1",
    kind = "ApplicationSet",
    namespaced,
    status = "ApplicationSetStatus",
    shortname = "appset",
    doc = "Fleet template: one generator produces parameter sets that render many Applications in this namespace",
    derive = "PartialEq",
    printcolumn(
        name = "GENERATED",
        type_ = "integer",
        json_path = ".status.generatedCount",
        description = "Number of Applications the last successful generation produced"
    ),
    printcolumn(
        name = "AGE",
        type_ = "date",
        json_path = ".metadata.creationTimestamp",
        description = "Age of the ApplicationSet"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSetSpec {
    /// Exactly one top-level generator (a `matrix` carries its two children).
    ///
    /// A list is used instead of a single field so the wire shape matches the documented
    /// `spec.generators[]` API; [`ApplicationSetSpec::validate`] enforces `len() == 1`.
    pub generators: Vec<ApplicationSetGenerator>,

    /// The `Application` template every generated parameter set is rendered into.
    pub template: ApplicationSetTemplate,

    /// Generation and deletion policy (non-destructive by default).
    #[serde(default)]
    pub sync_policy: ApplicationSetSyncPolicy,

    /// Periodic re-evaluation interval in seconds (default 180).
    #[serde(default = "default_requeue_after_seconds")]
    #[schemars(range(min = 1, max = 86_400))]
    pub requeue_after_seconds: u32,

    /// Optional lower ceiling on this object's fan-out (`1..=200`).
    ///
    /// Omitted means [`MAX_GENERATED_APPLICATIONS`]; a value above it is rejected, never clamped
    /// silently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 200))]
    pub max_generated_applications: Option<i64>,
}

fn default_requeue_after_seconds() -> u32 {
    DEFAULT_APPLICATIONSET_REQUEUE_AFTER_SECONDS
}

/// One parameter source of an `ApplicationSet`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum ApplicationSetGenerator {
    /// Static array of flat key/value maps.
    List(ListGenerator),
    /// Directory glob or parameter-file glob inside one Git repository.
    Git(GitGenerator),
    /// Label selector over registered cluster `Secret`s.
    Clusters(ClusterGenerator),
    /// Cartesian product of exactly two child generators.
    Matrix(MatrixGenerator),
}

/// `list` generator: static, in-memory parameter maps.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListGenerator {
    /// One parameter map per generated `Application`.
    #[serde(default)]
    pub elements: Vec<BTreeMap<String, String>>,
}

/// One directory glob of a `git` generator.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct GitDirectoryPattern {
    /// Repository-relative glob (`apps/*`, `envs/**`). `*` matches one path segment, `**` any number.
    pub path: String,
    /// Exclude matching directories instead of including them (a deny wins over every include).
    #[serde(default)]
    pub exclude: bool,
}

/// One parameter-file glob of a `git` generator.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct GitFilePattern {
    /// Repository-relative glob of YAML/JSON parameter files (`envs/*/config.yaml`).
    pub path: String,
    /// Exclude matching files instead of including them.
    #[serde(default)]
    pub exclude: bool,
}

/// `git` generator: parameter sets read from one repository revision.
///
/// `directories` and `files` are mutually exclusive; both are evaluated through the same
/// sanitized worktree, the guarded YAML parser ([`ferriscd_engine`]'s `parse_document` budgets), and
/// a bounded directory walk.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GitGenerator {
    /// Repository clone URL (`https://`, `ssh://`, SCP-style SSH, or a local test path).
    #[serde(rename = "repoURL")]
    pub repo_url: String,

    /// Branch, tag, `HEAD`, or a full 40-character commit SHA.
    #[serde(default = "default_target_revision")]
    pub revision: String,

    /// Directory globs (mutually exclusive with `files`).
    #[serde(default)]
    pub directories: Vec<GitDirectoryPattern>,

    /// Parameter-file globs (mutually exclusive with `directories`).
    #[serde(default)]
    pub files: Vec<GitFilePattern>,
}

fn default_target_revision() -> String {
    DEFAULT_TARGET_REVISION.to_owned()
}

/// `clusters` generator: the registered clusters a label selector matches.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterGenerator {
    /// Optional label selector; omitted selects every registered cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<ClusterSelector>,
}

/// Exact-match label selector (Kubernetes `matchLabels` semantics; no `matchExpressions`).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSelector {
    /// Label keys and values a cluster registration `Secret` must carry, all of them.
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

/// `matrix` generator: the Cartesian product of exactly two child generators.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MatrixGenerator {
    /// Exactly two children; the child *type* has no `matrix` variant, so nesting is
    /// unrepresentable and the output stays a product of two.
    #[serde(default)]
    pub generators: Vec<MatrixChildGenerator>,
}

/// A leaf generator, as a `matrix` child.
///
/// Deliberately **not** [`ApplicationSetGenerator`]: that enum contains `Matrix`, which would make
/// the schema recursive. Two things follow, and both matter:
///
/// * **A nested matrix cannot be expressed at all.** `spec.generators[].matrix.generators[]` accepts
///   only `list`, `git`, and `clusters`, so the product of a product (an unbounded fan-out shape)
///   is rejected by the API server's own schema instead of by a controller check.
/// * **The generated CRD stays structural.** A Kubernetes `CustomResourceDefinition` schema may not
///   contain JSON schema reference pointers (the API server rejects them outright), and a recursive
///   Rust type is exactly what makes the schema generator emit one. A CRD that cannot be applied is
///   a CRD that cannot ship, so the recursion is removed here rather than papered over.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MatrixChildGenerator {
    /// Static array of flat key/value maps.
    List(ListGenerator),
    /// Directory glob or parameter-file glob inside one Git repository.
    Git(GitGenerator),
    /// Label selector over registered cluster `Secret`s.
    Clusters(ClusterGenerator),
}

/// The `Application` an `ApplicationSet` renders, minus Kubernetes server-populated fields.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSetTemplate {
    /// Generated `Application` metadata (placeholders allowed; the name is DNS-1123 sanitized).
    pub metadata: ApplicationSetTemplateMetadata,
    /// Generated `Application` spec (placeholders allowed in its string fields).
    pub spec: ApplicationSpec,
}

/// Metadata of the generated `Application`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSetTemplateMetadata {
    /// Template for `metadata.name`; the rendered value is DNS-1123 sanitized.
    pub name: String,
    /// Additional labels (the `ferriscd.io/applicationset` label is always applied by the engine).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Annotations.
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

/// Generation and deletion policy of an `ApplicationSet`.
///
/// Both fields default to the non-destructive choice: an `ApplicationSet` deletion never removes
/// the generated `Application`s (and therefore never their workloads), and a generator that no
/// longer yields a parameter set does not prune its `Application` until pruning is opted in.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase", default)]
pub struct ApplicationSetSyncPolicy {
    /// Orphan (never delete) the generated `Application`s when this `ApplicationSet` is deleted.
    #[serde(default = "default_true")]
    pub preserve_resources_on_deletion: bool,

    /// Delete generated `Application`s the generators no longer produce (default `false`).
    #[serde(default)]
    pub prune: bool,
}

impl Default for ApplicationSetSyncPolicy {
    fn default() -> Self {
        Self {
            preserve_resources_on_deletion: true,
            prune: false,
        }
    }
}

fn default_true() -> bool {
    true
}

/// `ApplicationSet` `/status` subresource.
///
/// Kept as small as `Application.status`: the generation count plus standard conditions, never the
/// generated objects themselves (trap T9).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSetStatus {
    /// `metadata.generation` observed by the last evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Standard conditions (`Ready` is set on every pass, success or failure).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// How many `Application`s the last successful generation produced.
    #[serde(default)]
    pub generated_count: u32,
}

impl ApplicationSetStatus {
    /// Inserts or updates a condition, preserving `lastTransitionTime` while `status` is unchanged.
    pub fn set_condition(&mut self, condition: Condition) {
        match self
            .conditions
            .iter_mut()
            .find(|existing| existing.type_ == condition.type_)
        {
            Some(existing) if existing.status == condition.status => {
                existing.reason = condition.reason;
                existing.message = condition.message;
                existing.observed_generation = condition.observed_generation;
            }
            Some(existing) => *existing = condition,
            None => self.conditions.push(condition),
        }
    }

    /// Records `Ready=True`.
    pub fn mark_ready(
        &mut self,
        reason: impl Into<String>,
        message: impl Into<String>,
        last_transition_time: Time,
    ) {
        self.set_condition(Condition::ready(
            ConditionStatus::True,
            reason,
            message,
            last_transition_time,
        ));
    }

    /// Records `Ready=False`.
    pub fn mark_not_ready(
        &mut self,
        reason: impl Into<String>,
        message: impl Into<String>,
        last_transition_time: Time,
    ) {
        self.set_condition(Condition::ready(
            ConditionStatus::False,
            reason,
            message,
            last_transition_time,
        ));
    }

    /// Returns whether `Ready` is `True`.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.conditions
            .iter()
            .find(|condition| condition.type_ == crate::status::CONDITION_READY)
            .is_some_and(Condition::is_true)
    }
}

/// Why an [`ApplicationSetSpec`] is unusable.
///
/// Every variant is **terminal**: no amount of retrying changes the spec, so the controller
/// surfaces it as `Ready=False` instead of requeueing forever.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationSetSpecError {
    /// `spec.generators` was empty.
    #[error("spec.generators must contain exactly one generator, got none")]
    NoGenerator,
    /// `spec.generators` carried more than one entry.
    #[error(
        "spec.generators must contain exactly one generator, got {count}: combine them with a \
         `matrix` generator instead"
    )]
    MultipleGenerators {
        /// How many were configured.
        count: usize,
    },
    /// A `matrix` generator did not have exactly two children.
    #[error("a matrix generator must contain exactly two child generators, got {count}")]
    MatrixArity {
        /// How many children were configured.
        count: usize,
    },
    /// A `git` generator set both `directories` and `files`.
    #[error("a git generator must set either directories or files, never both")]
    GitSourceAmbiguous,
    /// A `git` generator set neither `directories` nor `files`.
    #[error("a git generator must set directories or files")]
    GitSourceMissing,
    /// `spec.template.metadata.name` was blank.
    #[error("spec.template.metadata.name must not be blank")]
    EmptyTemplateName,
    /// A `git` generator repository URL was blank.
    #[error("a git generator repoURL must not be blank")]
    EmptyRepoUrl,
    /// A `git` generator revision was blank.
    #[error("a git generator revision must not be blank")]
    EmptyRevision,
    /// A glob pattern was blank.
    #[error("a git generator path pattern must not be blank")]
    EmptyPattern,
    /// A glob pattern was absolute or contained a `..` segment.
    #[error(
        "the git generator path pattern {pattern:?} must be repository-relative and may not \
         contain a `..` segment"
    )]
    UnsafePattern {
        /// The rejected pattern.
        pattern: String,
    },
    /// A `list` element carried an empty or invalid parameter key.
    #[error(
        "the list generator parameter key {key:?} is not usable: keys must be non-empty and match \
         [A-Za-z0-9_.-]+"
    )]
    InvalidParameterKey {
        /// The rejected key.
        key: String,
    },
    /// `spec.maxGeneratedApplications` was outside `1..=200`.
    #[error("spec.maxGeneratedApplications must be between 1 and 200, got {value}")]
    MaxGeneratedOutOfRange {
        /// The rejected value.
        value: i64,
    },
    /// `spec.requeueAfterSeconds` was zero.
    #[error("spec.requeueAfterSeconds must be greater than zero")]
    ZeroRequeueAfter,
}

/// Whether `key` is usable as a `{{key}}` placeholder name.
///
/// Deliberately narrow: no braces, whitespace, brackets, or quoting, so the renderer never has to
/// interpret anything beyond a literal lookup. `[`, `]`, and `.` are excluded too — the indices the
/// `git` generator synthesizes (`path[1]`, `path.basename`) are produced internally, never written
/// by a user in a `list` element.
#[must_use]
pub fn is_valid_parameter_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Whether `pattern` is a repository-relative glob with no traversal segment.
fn is_relative_pattern(pattern: &str) -> bool {
    !pattern.starts_with('/')
        && !pattern.starts_with('\\')
        && !pattern.contains('\\')
        && !pattern
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
}

impl ApplicationSetSpec {
    /// The effective fan-out ceiling (`spec.maxGeneratedApplications`, else the hard maximum).
    #[must_use]
    pub fn effective_max_generated_applications(&self) -> usize {
        match self.max_generated_applications {
            Some(value) => usize::try_from(value).unwrap_or(0),
            None => usize::try_from(MAX_GENERATED_APPLICATIONS).unwrap_or(0),
        }
    }

    /// Validates the spec against the invariants the CRD schema cannot express.
    ///
    /// # Errors
    ///
    /// See [`ApplicationSetSpecError`]; every variant is terminal.
    pub fn validate(&self) -> Result<(), ApplicationSetSpecError> {
        match self.generators.len() {
            0 => return Err(ApplicationSetSpecError::NoGenerator),
            1 => {}
            count => return Err(ApplicationSetSpecError::MultipleGenerators { count }),
        }
        if self.template.metadata.name.trim().is_empty() {
            return Err(ApplicationSetSpecError::EmptyTemplateName);
        }
        if self.requeue_after_seconds == 0 {
            return Err(ApplicationSetSpecError::ZeroRequeueAfter);
        }
        if let Some(value) = self.max_generated_applications
            && !(MIN_GENERATED_APPLICATIONS..=MAX_GENERATED_APPLICATIONS).contains(&value)
        {
            return Err(ApplicationSetSpecError::MaxGeneratedOutOfRange { value });
        }
        // The top-level arity is already exactly one, so this validates that generator and, for a
        // matrix, both children.
        validate_generator(&self.generators[0])
    }
}

fn validate_generator(generator: &ApplicationSetGenerator) -> Result<(), ApplicationSetSpecError> {
    match generator {
        ApplicationSetGenerator::List(list) => validate_list(list),
        ApplicationSetGenerator::Git(git) => validate_git(git),
        ApplicationSetGenerator::Clusters(_) => Ok(()),
        ApplicationSetGenerator::Matrix(matrix) => {
            if matrix.generators.len() != 2 {
                return Err(ApplicationSetSpecError::MatrixArity {
                    count: matrix.generators.len(),
                });
            }
            for child in &matrix.generators {
                validate_child(child)?;
            }
            Ok(())
        }
    }
}

fn validate_child(child: &MatrixChildGenerator) -> Result<(), ApplicationSetSpecError> {
    match child {
        MatrixChildGenerator::List(list) => validate_list(list),
        MatrixChildGenerator::Git(git) => validate_git(git),
        MatrixChildGenerator::Clusters(_) => Ok(()),
    }
}

fn validate_list(list: &ListGenerator) -> Result<(), ApplicationSetSpecError> {
    for element in &list.elements {
        for key in element.keys() {
            if !is_valid_parameter_key(key) {
                return Err(ApplicationSetSpecError::InvalidParameterKey { key: key.clone() });
            }
        }
    }
    Ok(())
}

fn validate_git(git: &GitGenerator) -> Result<(), ApplicationSetSpecError> {
    if git.repo_url.trim().is_empty() {
        return Err(ApplicationSetSpecError::EmptyRepoUrl);
    }
    if git.revision.trim().is_empty() {
        return Err(ApplicationSetSpecError::EmptyRevision);
    }
    match (git.directories.is_empty(), git.files.is_empty()) {
        (true, true) => Err(ApplicationSetSpecError::GitSourceMissing),
        (false, false) => Err(ApplicationSetSpecError::GitSourceAmbiguous),
        _ => {
            let patterns: Vec<&str> = git
                .directories
                .iter()
                .map(|pattern| pattern.path.as_str())
                .chain(git.files.iter().map(|pattern| pattern.path.as_str()))
                .collect();
            for pattern in patterns {
                if pattern.trim().is_empty() {
                    return Err(ApplicationSetSpecError::EmptyPattern);
                }
                if !is_relative_pattern(pattern.trim()) {
                    return Err(ApplicationSetSpecError::UnsafePattern {
                        pattern: pattern.to_owned(),
                    });
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::jiff::Timestamp;
    use serde_json::Value;

    use super::*;

    const MINIMAL: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: ApplicationSet
metadata:
  name: payments
  namespace: ferriscd-system
spec:
  generators:
    - list:
        elements:
          - cluster: dev
            path: apps/api
          - cluster: prod
            path: apps/api
  template:
    metadata:
      name: api-{{cluster}}
    spec:
      project: default
      source:
        git:
          repoURL: https://github.com/example/payments.git
          path: "{{path}}"
      destination:
        cluster: "{{cluster}}"
        namespace: api
"#;

    fn parsed() -> crate::ApplicationSet {
        serde_saphyr::from_str(MINIMAL).expect("the minimal ApplicationSet must parse")
    }

    #[test]
    fn a_minimal_applicationset_parses_with_the_safe_defaults() {
        let appset = parsed();
        assert_eq!(appset.spec.generators.len(), 1);
        assert!(matches!(
            appset.spec.generators[0],
            ApplicationSetGenerator::List(_)
        ));
        assert!(
            appset.spec.sync_policy.preserve_resources_on_deletion,
            "deleting an ApplicationSet must never delete generated Applications by default"
        );
        assert!(
            !appset.spec.sync_policy.prune,
            "pruning stale generated Applications must stay opt-in"
        );
        assert_eq!(
            appset.spec.requeue_after_seconds,
            DEFAULT_APPLICATIONSET_REQUEUE_AFTER_SECONDS
        );
        assert_eq!(appset.spec.max_generated_applications, None);
        assert_eq!(
            appset.spec.effective_max_generated_applications(),
            usize::try_from(MAX_GENERATED_APPLICATIONS).expect("positive constant")
        );
        assert!(appset.spec.validate().is_ok());
    }

    #[test]
    fn an_explicit_destructive_policy_round_trips() {
        let mut appset = parsed();
        appset.spec.sync_policy = ApplicationSetSyncPolicy {
            preserve_resources_on_deletion: false,
            prune: true,
        };
        let rendered = serde_saphyr::to_string(&appset).expect("serializable");
        let reparsed: crate::ApplicationSet =
            serde_saphyr::from_str(&rendered).expect("must parse back");
        assert!(!reparsed.spec.sync_policy.preserve_resources_on_deletion);
        assert!(reparsed.spec.sync_policy.prune);

        // An explicitly empty `syncPolicy` also means "safe defaults", never "delete everything".
        let mut value: Value = serde_json::to_value(&appset).expect("serializable");
        value["spec"]["syncPolicy"] = serde_json::json!({});
        let reparsed: crate::ApplicationSet = serde_json::from_value(value).expect("must parse");
        assert!(reparsed.spec.sync_policy.preserve_resources_on_deletion);
        assert!(!reparsed.spec.sync_policy.prune);
    }

    #[test]
    fn every_generator_kind_is_representable() {
        let yaml = r#"
generators:
  - matrix:
      generators:
        - clusters:
            selector:
              matchLabels:
                env: prod
        - git:
            repoURL: https://github.com/example/config.git
            revision: v1.2.3
            directories:
              - path: apps/*
              - path: apps/legacy
                exclude: true
template:
  metadata:
    name: "{{cluster.name}}-{{path.basename}}"
    labels:
      team: payments
    annotations:
      ferriscd.io/note: generated
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
        path: "{{path}}"
    destination:
      cluster: "{{cluster.name}}"
      namespace: "{{path.basename}}"
"#;
        let spec: ApplicationSetSpec = serde_saphyr::from_str(yaml).expect("must parse");
        spec.validate()
            .expect("a matrix of clusters x directories is legal");
        let ApplicationSetGenerator::Matrix(matrix) = &spec.generators[0] else {
            panic!("expected a matrix");
        };
        assert!(matches!(
            matrix.generators[0],
            MatrixChildGenerator::Clusters(_)
        ));
        let MatrixChildGenerator::Git(git) = &matrix.generators[1] else {
            panic!("expected a git generator");
        };
        assert_eq!(git.revision, "v1.2.3");
        assert_eq!(git.directories.len(), 2);
        assert!(git.directories[1].exclude);
        assert_eq!(
            spec.template.metadata.labels.get("team"),
            Some(&"payments".to_owned())
        );
    }

    #[test]
    fn spec_validation_refuses_the_unsafe_shapes() {
        let base = parsed().spec;

        let mut empty = base.clone();
        empty.generators.clear();
        assert_eq!(empty.validate(), Err(ApplicationSetSpecError::NoGenerator));

        let mut both = base.clone();
        both.generators.push(ApplicationSetGenerator::Clusters(
            ClusterGenerator::default(),
        ));
        assert_eq!(
            both.validate(),
            Err(ApplicationSetSpecError::MultipleGenerators { count: 2 })
        );

        let git = |directories: Vec<GitDirectoryPattern>, files: Vec<GitFilePattern>| {
            ApplicationSetGenerator::Git(GitGenerator {
                repo_url: "https://github.com/example/config.git".to_owned(),
                revision: "HEAD".to_owned(),
                directories,
                files,
            })
        };
        let with_generator = |generator: ApplicationSetGenerator| {
            let mut spec = base.clone();
            spec.generators = vec![generator];
            spec
        };

        assert_eq!(
            with_generator(git(Vec::new(), Vec::new())).validate(),
            Err(ApplicationSetSpecError::GitSourceMissing)
        );
        assert_eq!(
            with_generator(git(
                vec![GitDirectoryPattern {
                    path: "apps/*".to_owned(),
                    exclude: false,
                }],
                vec![GitFilePattern {
                    path: "envs/*.yaml".to_owned(),
                    exclude: false,
                }],
            ))
            .validate(),
            Err(ApplicationSetSpecError::GitSourceAmbiguous)
        );
        for pattern in ["", "  "] {
            assert_eq!(
                with_generator(git(
                    vec![GitDirectoryPattern {
                        path: pattern.to_owned(),
                        exclude: false,
                    }],
                    Vec::new(),
                ))
                .validate(),
                Err(ApplicationSetSpecError::EmptyPattern)
            );
        }
        for pattern in ["/etc/passwd", "../secrets/*", "apps/../../etc", "./apps"] {
            assert_eq!(
                with_generator(git(
                    vec![GitDirectoryPattern {
                        path: pattern.to_owned(),
                        exclude: false,
                    }],
                    Vec::new(),
                ))
                .validate(),
                Err(ApplicationSetSpecError::UnsafePattern {
                    pattern: pattern.to_owned()
                }),
                "the pattern {pattern:?} must be refused"
            );
        }

        let mut arity = base.clone();
        arity.generators = vec![ApplicationSetGenerator::Matrix(MatrixGenerator {
            generators: vec![MatrixChildGenerator::Clusters(ClusterGenerator::default())],
        })];
        assert_eq!(
            arity.validate(),
            Err(ApplicationSetSpecError::MatrixArity { count: 1 })
        );

        let mut blank_name = base.clone();
        blank_name.template.metadata.name = "   ".to_owned();
        assert_eq!(
            blank_name.validate(),
            Err(ApplicationSetSpecError::EmptyTemplateName)
        );

        for value in [0_i64, MAX_GENERATED_APPLICATIONS + 1] {
            let mut out_of_range = base.clone();
            out_of_range.max_generated_applications = Some(value);
            assert_eq!(
                out_of_range.validate(),
                Err(ApplicationSetSpecError::MaxGeneratedOutOfRange { value })
            );
        }

        let mut zero_requeue = base.clone();
        zero_requeue.requeue_after_seconds = 0;
        assert_eq!(
            zero_requeue.validate(),
            Err(ApplicationSetSpecError::ZeroRequeueAfter)
        );
    }

    #[test]
    fn a_nested_matrix_cannot_even_be_parsed() {
        // `MatrixChildGenerator` has no `matrix` variant, so the product-of-a-product shape — the
        // one that would make the fan-out unbounded — is refused by the wire format itself, before
        // any controller check runs (and without a recursive `$ref` in the CRD schema).
        let yaml = r#"
generators:
  - matrix:
      generators:
        - matrix:
            generators:
              - clusters: {}
              - clusters: {}
        - clusters: {}
template:
  metadata:
    name: assert-nested
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
    destination:
      cluster: in-cluster
      namespace: payments
"#;
        let error = serde_saphyr::from_str::<ApplicationSetSpec>(yaml)
            .expect_err("a nested matrix must not deserialize");
        assert!(
            error.to_string().contains("matrix"),
            "the error must name the unsupported generator: {error}"
        );
    }

    #[test]
    fn list_parameter_keys_are_restricted_to_flat_placeholders() {
        let mut spec = parsed().spec;
        spec.generators = vec![ApplicationSetGenerator::List(ListGenerator {
            elements: vec![BTreeMap::from([("bad{key}".to_owned(), "x".to_owned())])],
        })];
        assert_eq!(
            spec.validate(),
            Err(ApplicationSetSpecError::InvalidParameterKey {
                key: "bad{key}".to_owned()
            })
        );
        assert!(is_valid_parameter_key("cluster.name"));
        assert!(is_valid_parameter_key("path-2"));
        assert!(!is_valid_parameter_key(""));
        assert!(!is_valid_parameter_key("path[1]"));
    }

    #[test]
    fn effective_cap_can_only_lower_the_hard_maximum() {
        let mut spec = parsed().spec;
        spec.max_generated_applications = Some(3);
        assert_eq!(spec.effective_max_generated_applications(), 3);
        spec.max_generated_applications = Some(MAX_GENERATED_APPLICATIONS);
        assert_eq!(
            spec.effective_max_generated_applications(),
            usize::try_from(MAX_GENERATED_APPLICATIONS).expect("positive constant")
        );
    }

    #[test]
    fn status_conditions_preserve_the_transition_time() {
        let first = Time(Timestamp::now());
        let mut status = ApplicationSetStatus::default();
        status.mark_ready("ApplicationsGenerated", "2 generated", first.clone());
        assert!(status.is_ready());
        assert_eq!(status.conditions.len(), 1);
        assert_eq!(status.conditions[0].last_transition_time, first);

        // A repeat with the same status refreshes reason/message but never the transition time.
        status.mark_ready(
            "ApplicationsGenerated",
            "3 generated",
            Time(Timestamp::now()),
        );
        assert_eq!(status.conditions[0].last_transition_time, first);
        assert_eq!(status.conditions[0].message, "3 generated");

        // A flip to False does move it.
        status.mark_not_ready("FanOutLimitExceeded", "too many", Time(Timestamp::now()));
        assert!(!status.is_ready());
        assert_ne!(status.conditions[0].last_transition_time, first);
    }

    #[test]
    fn generated_count_is_part_of_the_status_contract() {
        let mut appset = parsed();
        appset.status = Some(ApplicationSetStatus {
            observed_generation: Some(4),
            generated_count: 2,
            ..ApplicationSetStatus::default()
        });
        let value = serde_json::to_value(&appset).expect("serializable");
        assert_eq!(value["status"]["observedGeneration"], 4);
        assert_eq!(value["status"]["generatedCount"], 2);
        assert!(
            value["status"].get("conditions").is_none(),
            "an empty condition list must not be serialized"
        );
    }
}
