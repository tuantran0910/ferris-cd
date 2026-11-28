//! `ApplicationSet` generation engine (`T19.3`): generators, flat `{{key}}` templating, the fan-out
//! cap guard, and the ownership/prune/deletion planner.
//!
//! The module is pure and offline. It never talks to Kubernetes, never reads a `Secret`, and never
//! shells out: Git checkouts and the cluster registry arrive through the two narrow traits in
//! [`generators`], so both are trivially faked in tests. The controller owns every API read/write and
//! calls the planner here to decide *what* to write.
//!
//! # Safety model
//!
//! * **Bounded fan-out.** [`MAX_GENERATED_APPS`] is a hard ceiling. An expansion over the effective
//!   cap is refused (`Ready=False`), never truncated, and the product of a `matrix` is checked
//!   before it is materialized.
//! * **No partial plans.** [`plan_reconcile`] returns **either** a complete plan **or** an error.
//!   The controller therefore never writes (or deletes) anything when the generators, the template,
//!   or the ownership checks failed, which is what makes a transient Git error non-destructive.
//! * **Ownership before overwrite.** A desired name that already exists as an unmanaged or
//!   foreign-owned `Application` is a terminal conflict; nothing is adopted, nothing is overwritten.
//! * **Non-destructive deletion.** [`plan_deletion`] **orphans** the generated `Application`s when
//!   `spec.syncPolicy.preserveResourcesOnDeletion` is `true` (the default), and it only ever acts on
//!   objects this `ApplicationSet` provably owns.
//! * **Opt-in pruning.** A generated `Application` the generators no longer produce is kept until
//!   `spec.syncPolicy.prune` is `true`, so a changed glob never mass-deletes a fleet.
//! * **Identity, not just a name.** Ownership matches the `ownerReference` name **and** uid, and a
//!   prune/delete carries the `uid` the plan read so the controller can send it as the delete
//!   precondition. A name alone is not identity: deleting and re-creating an `ApplicationSet` (or a
//!   generated `Application`) under the same name must never let the new object act on the old one's
//!   fleet (a list-then-delete TOCTOU).
//!
//! # What this module does not prove
//!
//! The roadmap's non-functional requirement — "generator evaluation of a 200-application `matrix`
//! completes in `< 500 ms` in memory" — is **not** asserted anywhere in this crate. The tests are
//! timing-free on purpose (no sleeps, no wall-clock budgets, so nothing is flaky on a loaded CI
//! runner), and the 200-application test only proves the expansion is exactly at the cap, stays in
//! memory, and is deterministic. The latency number has to be measured separately (a criterion-style
//! benchmark), and no CI gate claims it today.

pub mod generators;
pub mod template;

use std::collections::BTreeSet;

use ferriscd_crd::applicationset::{
    APPLICATIONSET_LABEL, ApplicationSet, ApplicationSetSpecError, MAX_GENERATED_APPLICATIONS,
};
use ferriscd_crd::{API_GROUP, Application};
use kube::ResourceExt;

pub use generators::{
    ClusterParamSource, ClusterRegistration, GeneratorContext, GitParameterSource, ParamMap,
    expand, glob_matches,
};
pub use template::{
    RenderedApplication, TemplateError, is_placeholder_key, render_placeholders, render_template,
    sanitize_dns1123,
};

/// Absolute ceiling on the number of `Application`s one `ApplicationSet` may generate.
///
/// Aliases the CRD's own constant, so the schema's `maximum` and the engine's refusal are the same
/// number (a test asserts it).
pub const MAX_GENERATED_APPS: usize = MAX_GENERATED_APPLICATIONS as usize;

/// Everything that can stop an `ApplicationSet` pass.
///
/// The split between retryable and terminal matters to the controller: a transient Git/disk/cluster
/// read is retried on the short backoff, while a bad spec, template, fan-out, or conflict waits for
/// the object to change. Messages name the offending object and field and never carry a parameter
/// *value* that could be a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplicationSetError {
    /// The `ApplicationSet` spec is unusable.
    #[error(transparent)]
    Spec(#[from] ApplicationSetSpecError),

    /// The template could not be rendered.
    #[error(transparent)]
    Template(#[from] TemplateError),

    /// The generators would produce more `Application`s than the cap allows.
    #[error(
        "the generators would produce {requested} Applications, which exceeds the cap of {limit} \
         (hard maximum {hard_limit}); narrow the generators or lower the template fan-out"
    )]
    FanOutLimitExceeded {
        /// How many `Application`s the generators produced.
        requested: usize,
        /// The effective cap (`spec.maxGeneratedApplications`, else the hard maximum).
        limit: usize,
        /// [`MAX_GENERATED_APPS`].
        hard_limit: usize,
    },

    /// Two parameter sets rendered the same `Application` name.
    #[error(
        "the generators rendered the Application name {name:?} more than once; a template metadata.\
         name must be unique per parameter set"
    )]
    DuplicateName {
        /// The duplicated name.
        name: String,
    },

    /// An existing `Application` of the same name is not owned by this `ApplicationSet`.
    #[error(
        "refusing to overwrite Application {name:?}: {owner} (an ApplicationSet only manages the \
         Applications it owns)"
    )]
    Conflict {
        /// The conflicting name.
        name: String,
        /// Who owns it.
        owner: String,
    },

    /// A generator could not produce parameters (Git fetch, disk read, cluster registry).
    ///
    /// `retryable` is **carried, not assumed**: a generator failure wraps a `RepoError` (or a disk
    /// read) whose own classification decides whether the next pass can possibly succeed. Reporting
    /// every generator failure as retryable would requeue a repository the credentials can never
    /// open, and reporting none of them as retryable would park an `ApplicationSet` on a dropped
    /// connection. Construct it through [`ApplicationSetError::generator`] so the bit is never
    /// forgotten.
    #[error("the {generator} generator failed: {message}")]
    Generator {
        /// Generator kind (`git`, `clusters`, `matrix`).
        generator: &'static str,
        /// What went wrong (content-free).
        message: String,
        /// Whether retrying the same inputs can succeed.
        retryable: bool,
    },

    /// A Git parameter file was unusable.
    #[error("the parameter file {path:?} is unusable: {message}")]
    ParameterFile {
        /// Repository-relative path of the file.
        path: String,
        /// What went wrong (never the file's contents).
        message: String,
    },

    /// A Git worktree held more directory entries than one generator may walk.
    #[error(
        "the worktree holds more than {limit} entries; a generator glob must stay bounded (narrow \
         the repository or the generator pattern)"
    )]
    WalkBudgetExceeded {
        /// [`generators::MAX_GIT_WALK_ENTRIES`].
        limit: usize,
    },
}

impl ApplicationSetError {
    /// Builds a generator failure carrying its retry classification.
    #[must_use]
    pub fn generator(generator: &'static str, message: impl Into<String>, retryable: bool) -> Self {
        Self::Generator {
            generator,
            message: message.into(),
            retryable,
        }
    }

    /// Whether retrying the same inputs can succeed (a transient read), or not (the object must
    /// change).
    ///
    /// Every variant is terminal except a generator failure that carried `retryable: true` from the
    /// repository/disk error underneath it.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Generator { retryable, .. } => *retryable,
            Self::Spec(_)
            | Self::Template(_)
            | Self::FanOutLimitExceeded { .. }
            | Self::DuplicateName { .. }
            | Self::Conflict { .. }
            | Self::ParameterFile { .. }
            | Self::WalkBudgetExceeded { .. } => false,
        }
    }

    /// A bounded, machine-readable condition reason.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Spec(_) => "InvalidApplicationSetSpec",
            Self::Template(_) => "TemplateError",
            Self::FanOutLimitExceeded { .. } => "FanOutLimitExceeded",
            Self::DuplicateName { .. } => "DuplicateApplicationName",
            Self::Conflict { .. } => "ApplicationConflict",
            Self::Generator { .. } => "GeneratorError",
            Self::ParameterFile { .. } => "InvalidParameterFile",
            Self::WalkBudgetExceeded { .. } => "WalkBudgetExceeded",
        }
    }
}

/// One full generation: the rendered `Application`s, sorted by name.
///
/// Sorting is part of the contract, not cosmetic: it makes the plan (and therefore the API writes
/// and the `/status` message) byte-stable for identical inputs, whatever order the generators
/// discovered things in.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Generation {
    applications: Vec<RenderedApplication>,
}

impl Generation {
    /// How many `Application`s the generation produced.
    #[must_use]
    pub fn len(&self) -> usize {
        self.applications.len()
    }

    /// Whether the generation is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.applications.is_empty()
    }

    /// The rendered `Application`s, sorted by name.
    #[must_use]
    pub fn applications(&self) -> &[RenderedApplication] {
        &self.applications
    }

    /// The generated names, sorted.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.applications
            .iter()
            .map(|rendered| rendered.application.name_any())
            .collect()
    }
}

/// Expands an `ApplicationSet`'s generator and renders every parameter set.
///
/// # Errors
///
/// See [`ApplicationSetError`]; the spec is validated first, so nothing is expanded for an unusable
/// object.
pub async fn generate(
    appset: &ApplicationSet,
    clusters: &dyn ClusterParamSource,
    git: &dyn GitParameterSource,
) -> Result<Generation, ApplicationSetError> {
    appset.spec.validate()?;
    let limit = appset.spec.effective_max_generated_applications();
    let context = GeneratorContext::new(clusters, git, limit);
    let Some(generator) = appset.spec.generators.first() else {
        return Err(ApplicationSetError::Spec(
            ApplicationSetSpecError::NoGenerator,
        ));
    };
    let params = expand(&context, generator).await?;
    if params.len() > limit {
        return Err(ApplicationSetError::FanOutLimitExceeded {
            requested: params.len(),
            limit,
            hard_limit: MAX_GENERATED_APPS,
        });
    }

    let mut applications = Vec::with_capacity(params.len());
    for params in &params {
        applications.push(render_template(appset, params)?);
    }
    applications.sort_by(|left, right| {
        left.application
            .name_any()
            .cmp(&right.application.name_any())
    });
    // Sorted first, so the reported duplicate is always the lexicographically first collision.
    for pair in applications.windows(2) {
        let (left, right) = (&pair[0].application, &pair[1].application);
        if left.name_any() == right.name_any() {
            return Err(ApplicationSetError::DuplicateName {
                name: left.name_any(),
            });
        }
    }
    Ok(Generation { applications })
}

/// Who owns an existing `Application`, as far as this `ApplicationSet` is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// A same-namespace `ownerReference` to this `ApplicationSet` (and the generated label).
    Managed,
    /// No owner reference and no generated label: an operator's hand-written `Application`.
    Unmanaged,
    /// Owned by something else (another `ApplicationSet` or another kind), or carrying the generated
    /// label without the matching owner reference.
    Foreign {
        /// The owner, rendered for the conflict message.
        owner: String,
    },
}

/// Classifies `app` relative to `appset`.
///
/// The `ownerReference` is authoritative — it is what Kubernetes garbage collection acts on — and
/// the label alone is never enough to adopt an object. A generated label *without* our owner
/// reference is deliberately **foreign**: someone hand-copied a generated `Application`, and
/// silently taking it over would let a template rewrite an object its author owns.
///
/// The reference must match **both** the name and the uid the `ApplicationSet` currently carries.
/// A name match with a different uid is a *stale* reference: the `ApplicationSet` was deleted and
/// re-created under the same name (or the object was copied from a previous incarnation), and
/// adopting it would let a fresh `ApplicationSet` rewrite — and, with pruning, delete — a fleet the
/// previous object generated.
#[must_use]
pub fn ownership(app: &Application, appset: &ApplicationSet) -> Ownership {
    let appset_name = appset.name_any();
    let appset_namespace = appset.namespace().unwrap_or_default();
    if app.namespace().unwrap_or_default() != appset_namespace {
        return Ownership::Foreign {
            owner: format!(
                "it lives in namespace {:?} instead of the ApplicationSet's own {:?}",
                app.namespace().unwrap_or_default(),
                appset_namespace
            ),
        };
    }
    if let Some(references) = &app.metadata.owner_references {
        for reference in references {
            if reference.api_version.starts_with(API_GROUP) && reference.kind == "ApplicationSet" {
                if reference.name != appset_name {
                    return Ownership::Foreign {
                        owner: format!("it is owned by ApplicationSet/{:?}", reference.name),
                    };
                }
                if let Some(uid) = appset.metadata.uid.as_deref()
                    && reference.uid != uid
                {
                    return Ownership::Foreign {
                        owner: format!(
                            "its ownerReference names this ApplicationSet but carries the stale uid \
                             {:?} (the current uid is {uid:?}, so this Application belongs to a \
                             previous incarnation of the name)",
                            reference.uid
                        ),
                    };
                }
                return Ownership::Managed;
            }
        }
        if let Some(reference) = references.first() {
            return Ownership::Foreign {
                owner: format!(
                    "it is owned by {}/{name:?}",
                    reference.kind,
                    name = reference.name
                ),
            };
        }
    }
    match app.labels().get(APPLICATIONSET_LABEL) {
        Some(label) if label == &appset_name => Ownership::Foreign {
            owner: format!(
                "it carries {APPLICATIONSET_LABEL}={label:?} but has no ownerReference to this \
                 ApplicationSet"
            ),
        },
        Some(label) => Ownership::Foreign {
            owner: format!("it already carries {APPLICATIONSET_LABEL}={label:?}"),
        },
        None => Ownership::Unmanaged,
    }
}

/// What the controller should do with one generated `Application`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileAction {
    /// It does not exist yet.
    Create,
    /// It exists, is owned by this `ApplicationSet`, and differs from the rendered template.
    Update,
    /// It exists and already matches the rendered template byte for byte (labels, annotations,
    /// owner reference, spec): no write at all.
    Skip,
}

/// One desired `Application` plus the write it needs.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedApplication {
    /// The rendered `Application`.
    pub rendered: RenderedApplication,
    /// The write to perform.
    pub action: ReconcileAction,
}

/// What to do with a generated `Application` the generators no longer produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PruneAction {
    /// Delete it (`spec.syncPolicy.prune: true`).
    Delete,
    /// Keep it (`prune` is off: the safe default).
    Keep,
}

/// One prune decision.
///
/// `uid` is the identity of the object the plan was built from, and the controller sends it as the
/// `delete` precondition. Without it a prune is a list-then-delete race: the `Application` may be
/// deleted and re-created under the same name between the list and the delete, and the delete would
/// then destroy an object this `ApplicationSet` never owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneDecision {
    /// Name of the generated `Application`.
    pub name: String,
    /// `metadata.uid` observed when the plan was built (`None` only for an unpersisted fixture).
    pub uid: Option<String>,
    /// Whether to delete or keep it.
    pub action: PruneAction,
}

/// The complete write plan for one pass.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ReconcilePlan {
    /// Every desired `Application`, sorted by name.
    pub applications: Vec<PlannedApplication>,
    /// Every owned `Application` the generators dropped, sorted by name.
    pub prune: Vec<PruneDecision>,
}

impl ReconcilePlan {
    /// How many writes (`Create`/`Update`) the plan needs.
    #[must_use]
    pub fn writes(&self) -> usize {
        self.applications
            .iter()
            .filter(|planned| planned.action != ReconcileAction::Skip)
            .count()
    }

    /// How many prunes the plan performs.
    #[must_use]
    pub fn deletions(&self) -> usize {
        self.prune
            .iter()
            .filter(|decision| decision.action == PruneAction::Delete)
            .count()
    }
}

/// Builds the write plan for one successful generation.
///
/// # Errors
///
/// [`ApplicationSetError::Conflict`] when a desired name already exists as an `Application` this
/// `ApplicationSet` does not own. The whole plan is refused, so the controller makes no partial
/// change.
pub fn plan_reconcile(
    appset: &ApplicationSet,
    generation: &Generation,
    existing: &[Application],
) -> Result<ReconcilePlan, ApplicationSetError> {
    let namespace = appset.namespace().unwrap_or_default();
    let mut applications = Vec::with_capacity(generation.len());
    let desired: BTreeSet<String> = generation
        .applications()
        .iter()
        .map(|rendered| rendered.application.name_any())
        .collect();

    for rendered in generation.applications() {
        let name = rendered.application.name_any();
        let current = existing
            .iter()
            .find(|app| app.name_any() == name && app.namespace().unwrap_or_default() == namespace);
        match current {
            None => applications.push(PlannedApplication {
                rendered: rendered.clone(),
                action: ReconcileAction::Create,
            }),
            Some(current) => match ownership(current, appset) {
                Ownership::Managed => {
                    let action = if application_matches(current, &rendered.application) {
                        ReconcileAction::Skip
                    } else {
                        ReconcileAction::Update
                    };
                    applications.push(PlannedApplication {
                        rendered: rendered.clone(),
                        action,
                    });
                }
                Ownership::Unmanaged => {
                    return Err(ApplicationSetError::Conflict {
                        name,
                        owner: "it is an unmanaged Application (no ownerReference)".to_owned(),
                    });
                }
                Ownership::Foreign { owner } => {
                    return Err(ApplicationSetError::Conflict { name, owner });
                }
            },
        }
    }

    let prune = if appset.spec.sync_policy.prune {
        PruneAction::Delete
    } else {
        PruneAction::Keep
    };
    let mut decisions: Vec<PruneDecision> = existing
        .iter()
        .filter(|app| app.namespace().unwrap_or_default() == namespace)
        // Only objects this ApplicationSet provably owns may ever be pruned.
        .filter(|app| ownership(app, appset) == Ownership::Managed)
        .filter(|app| !desired.contains(&app.name_any()))
        .map(|app| PruneDecision {
            name: app.name_any(),
            uid: app.metadata.uid.clone(),
            action: prune,
        })
        .collect();
    decisions.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(ReconcilePlan {
        applications,
        prune: decisions,
    })
}

/// Whether `existing` already carries everything the rendered `Application` would set.
///
/// Only the fields the `ApplicationSet` owns are compared: the spec, the template labels and
/// annotations (existing extra labels are left alone), and the `ApplicationSet` owner reference.
/// Status, the tracking annotation, and anything the controller adds are ignored, so a steady-state
/// pass performs no write.
#[must_use]
pub fn application_matches(existing: &Application, rendered: &Application) -> bool {
    if existing.spec != rendered.spec {
        return false;
    }
    let existing_labels = existing.labels();
    if !rendered
        .labels()
        .iter()
        .all(|(key, value)| existing_labels.get(key) == Some(value))
    {
        return false;
    }
    let empty = std::collections::BTreeMap::new();
    let rendered_annotations = rendered.metadata.annotations.as_ref().unwrap_or(&empty);
    let existing_annotations = existing.metadata.annotations.clone().unwrap_or_default();
    if !rendered_annotations
        .iter()
        .all(|(key, value)| existing_annotations.get(key) == Some(value))
    {
        return false;
    }
    let Some(rendered_owner) = rendered
        .metadata
        .owner_references
        .as_ref()
        .and_then(|references| references.first())
    else {
        return false;
    };
    existing
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|references| {
            references.iter().any(|reference| {
                reference.uid == rendered_owner.uid && reference.kind == rendered_owner.kind
            })
        })
}

/// What to do with one owned `Application` when the `ApplicationSet` is deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionAction {
    /// Drop the controller's `ownerReference` and keep the `Application` (and its workloads).
    Orphan,
    /// Delete the generated `Application` (`preserveResourcesOnDeletion: false`).
    Delete,
}

/// One generated `Application` the deletion plan acts on.
///
/// `uid` is what the plan read, and the controller sends it as the `delete` precondition (see
/// [`PruneDecision::uid`]); orphaning is a `metadata.ownerReferences` patch on the same object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionTarget {
    /// Name of the generated `Application`.
    pub name: String,
    /// `metadata.uid` observed when the plan was built.
    pub uid: Option<String>,
    /// `Orphan` or `Delete`.
    pub action: DeletionAction,
}

/// The complete deletion plan for one `ApplicationSet` that is going away.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeletionPlan {
    /// Whether the generated `Application`s are preserved (orphaned) rather than deleted.
    pub preserved: bool,
    /// One action per owned `Application`, sorted by name.
    pub actions: Vec<DeletionTarget>,
}

/// Plans what to do with the generated `Application`s of a **deleted** `ApplicationSet`.
///
/// `preserveResourcesOnDeletion` (default `true`) decides between orphaning and deleting; only
/// objects this `ApplicationSet` owns are ever touched. The controller runs this from the
/// `ApplicationSet` finalizer, so Kubernetes garbage collection — which follows
/// `metadata.ownerReferences` — cannot delete the children before the decision is applied.
#[must_use]
pub fn plan_deletion(appset: &ApplicationSet, existing: &[Application]) -> DeletionPlan {
    let preserved = appset.spec.sync_policy.preserve_resources_on_deletion;
    let action = if preserved {
        DeletionAction::Orphan
    } else {
        DeletionAction::Delete
    };
    let namespace = appset.namespace().unwrap_or_default();
    let mut actions: Vec<DeletionTarget> = existing
        .iter()
        .filter(|app| app.namespace().unwrap_or_default() == namespace)
        .filter(|app| ownership(app, appset) == Ownership::Managed)
        .map(|app| DeletionTarget {
            name: app.name_any(),
            uid: app.metadata.uid.clone(),
            action,
        })
        .collect();
    actions.sort_by(|left, right| left.name.cmp(&right.name));
    DeletionPlan { preserved, actions }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ferriscd_crd::APPLICATIONSET_FINALIZER;
    use ferriscd_crd::applicationset::{
        ApplicationSetGenerator, ApplicationSetSyncPolicy, ListGenerator, MatrixChildGenerator,
        MatrixGenerator,
    };
    use ferriscd_crd::status::ConditionStatus;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;

    use super::*;
    use crate::repo::{RepoCheckout, RepoFuture};
    use ferriscd_crd::applicationset::{ClusterGenerator, GitGenerator};

    struct FakeClusters(Vec<ClusterRegistration>);
    impl ClusterParamSource for FakeClusters {
        fn clusters(&self) -> Vec<ClusterRegistration> {
            self.0.clone()
        }
    }

    struct FakeGit;
    impl GitParameterSource for FakeGit {
        fn checkout<'a>(
            &'a self,
            _repo_url: &'a str,
            _revision: &'a str,
        ) -> RepoFuture<'a, RepoCheckout> {
            Box::pin(async {
                Err(crate::repo::RepoError::InvalidUrl {
                    url: "<redacted>".to_owned(),
                    reason: "the fixture has no checkout".to_owned(),
                })
            })
        }
    }

    fn appset(name: &str, spec_yaml: &str) -> ApplicationSet {
        let spec: ferriscd_crd::ApplicationSetSpec =
            serde_saphyr::from_str(spec_yaml).expect("the fixture spec must parse");
        let mut appset = ApplicationSet::new(name, spec);
        appset.metadata.namespace = Some("ferriscd-system".to_owned());
        appset.metadata.uid = Some(format!("uid-{name}"));
        appset
    }

    fn list_appset(name: &str) -> ApplicationSet {
        appset(
            name,
            r#"
generators:
  - list:
      elements:
        - env: prod
          path: apps/web
        - env: dev
          path: apps/api
template:
  metadata:
    name: "{{path}}-{{env}}"
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
        path: "{{path}}"
    destination:
      cluster: in-cluster
      namespace: "{{env}}"
"#,
        )
    }

    fn existing(name: &str, generation: &Generation) -> Application {
        let rendered = generation
            .applications()
            .iter()
            .find(|rendered| rendered.application.name_any() == name)
            .expect("the fixture name is generated")
            .application
            .clone();
        let mut app = rendered;
        app.metadata.uid = Some(format!("uid-{name}"));
        app
    }

    fn foreign(name: &str, owner_kind: &str, owner_name: &str) -> Application {
        let mut app = Application::new(name, list_appset("x").spec.template.spec.clone());
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        app.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: format!("{API_GROUP}/v1alpha1"),
                kind: owner_kind.to_owned(),
                name: owner_name.to_owned(),
                uid: format!("uid-{owner_name}"),
                controller: Some(true),
                block_owner_deletion: Some(true),
            },
        ]);
        app
    }

    #[tokio::test]
    async fn generation_is_sorted_and_deterministic() {
        let appset = list_appset("fleet");
        let git = FakeGit;
        let clusters = FakeClusters(Vec::new());
        let first = generate(&appset, &clusters, &git)
            .await
            .expect("must generate");
        let second = generate(&appset, &clusters, &git)
            .await
            .expect("must generate");
        assert_eq!(first, second);
        let names: Vec<String> = first
            .applications()
            .iter()
            .map(|rendered| rendered.application.name_any())
            .collect();
        assert_eq!(names, vec!["apps-api-dev", "apps-web-prod"]);
        assert_eq!(first.len(), 2);
        assert_eq!(first.names(), vec!["apps-api-dev", "apps-web-prod"]);
        assert_eq!(
            first.applications()[0]
                .application
                .spec
                .destination
                .namespace,
            "dev"
        );
    }

    #[tokio::test]
    async fn duplicate_rendered_names_are_refused_deterministically() {
        let appset = appset(
            "fleet",
            r#"
generators:
  - list:
      elements:
        - env: prod
        - env: prod
        - env: dev
template:
  metadata:
    name: api-{{env}}
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
    destination:
      cluster: in-cluster
      namespace: payments
"#,
        );
        let error = generate(&appset, &FakeClusters(Vec::new()), &FakeGit)
            .await
            .expect_err("duplicate names must be refused");
        assert_eq!(
            error,
            ApplicationSetError::DuplicateName {
                name: "api-prod".to_owned()
            }
        );
        assert_eq!(error.reason(), "DuplicateApplicationName");
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn the_spec_is_validated_before_anything_is_expanded() {
        let mut appset = list_appset("fleet");
        appset.spec.generators = vec![ApplicationSetGenerator::Matrix(MatrixGenerator {
            generators: vec![MatrixChildGenerator::Git(GitGenerator {
                repo_url: String::new(),
                revision: "HEAD".to_owned(),
                directories: Vec::new(),
                files: Vec::new(),
            })],
        })];
        let error = generate(&appset, &FakeClusters(Vec::new()), &FakeGit)
            .await
            .expect_err("an invalid matrix is refused");
        assert!(matches!(error, ApplicationSetError::Spec(_)));
        assert_eq!(error.reason(), "InvalidApplicationSetSpec");
    }

    #[tokio::test]
    async fn planning_creates_updates_skips_and_prunes_only_owned_applications() {
        let appset = list_appset("fleet");
        let generation = generate(&appset, &FakeClusters(Vec::new()), &FakeGit)
            .await
            .expect("must generate");

        // Nothing exists: both are creates.
        let plan = plan_reconcile(&appset, &generation, &[]).expect("must plan");
        assert_eq!(plan.writes(), 2);
        assert!(
            plan.applications
                .iter()
                .all(|planned| planned.action == ReconcileAction::Create)
        );

        // One already converges, one drifts, one stale generated Application exists, and one
        // hand-written Application must be left alone.
        let mut converged = existing("apps-api-dev", &generation);
        converged
            .metadata
            .labels
            .get_or_insert_with(BTreeMap::new)
            .insert(
                ferriscd_crd::annotations::REFRESH.to_owned(),
                "ignored".to_owned(),
            );
        let mut drifted = existing("apps-web-prod", &generation);
        drifted.spec.destination.namespace = "somewhere-else".to_owned();
        let mut stale = existing("apps-web-prod", &generation);
        stale.metadata.name = Some("apps-legacy-prod".to_owned());
        stale.metadata.uid = Some("uid-apps-legacy-prod".to_owned());
        stale
            .metadata
            .labels
            .get_or_insert_with(BTreeMap::new)
            .insert(APPLICATIONSET_LABEL.to_owned(), "fleet".to_owned());
        let hand_written = {
            let mut app =
                Application::new("hand-written", list_appset("x").spec.template.spec.clone());
            app.metadata.namespace = Some("ferriscd-system".to_owned());
            app
        };

        let existing_apps = vec![
            converged.clone(),
            drifted,
            stale.clone(),
            hand_written.clone(),
        ];
        let plan = plan_reconcile(&appset, &generation, &existing_apps).expect("must plan");
        assert_eq!(plan.applications.len(), 2);
        assert_eq!(
            plan.applications[0].action,
            ReconcileAction::Skip,
            "a converged Application must not be rewritten"
        );
        assert_eq!(plan.applications[1].action, ReconcileAction::Update);
        assert_eq!(plan.writes(), 1);
        assert_eq!(plan.prune.len(), 1);
        assert_eq!(plan.prune[0].name, "apps-legacy-prod");
        assert_eq!(
            plan.prune[0].uid.as_deref(),
            Some("uid-apps-legacy-prod"),
            "a prune decision carries the uid it read, so the delete can be preconditioned"
        );
        assert_eq!(
            plan.prune[0].action,
            PruneAction::Keep,
            "pruning is opt-in: a stale generated Application is kept by default"
        );
        assert_eq!(plan.deletions(), 0);

        // Opting in to prune turns the same stale entry into a delete — and still never touches the
        // hand-written Application.
        let mut pruning = appset.clone();
        pruning.spec.sync_policy = ApplicationSetSyncPolicy {
            preserve_resources_on_deletion: true,
            prune: true,
        };
        let plan = plan_reconcile(&pruning, &generation, &existing_apps).expect("must plan");
        assert_eq!(plan.prune.len(), 1);
        assert_eq!(plan.prune[0].action, PruneAction::Delete);
        assert_eq!(plan.deletions(), 1);
    }

    #[tokio::test]
    async fn conflicting_applications_are_refused_and_no_plan_is_returned() {
        let appset = list_appset("fleet");
        let generation = generate(&appset, &FakeClusters(Vec::new()), &FakeGit)
            .await
            .expect("must generate");

        for (label, owner_kind, owner_name) in [
            ("unmanaged", "", ""),
            ("foreign appset", "ApplicationSet", "other-fleet"),
            ("operator-owned", "Application", "hand-written"),
        ] {
            let mut conflicting = if owner_kind.is_empty() {
                let mut app = Application::new("apps-api-dev", appset.spec.template.spec.clone());
                app.metadata.namespace = Some("ferriscd-system".to_owned());
                app
            } else {
                foreign("apps-api-dev", owner_kind, owner_name)
            };
            conflicting.spec = generation.applications()[0].application.spec.clone();
            let error = plan_reconcile(&appset, &generation, &[conflicting]).expect_err(label);
            assert!(
                matches!(error, ApplicationSetError::Conflict { .. }),
                "{label}: expected a conflict, got {error:?}"
            );
            assert_eq!(error.reason(), "ApplicationConflict");
            assert!(!error.is_retryable());
        }
    }

    #[test]
    fn a_generated_label_without_the_owner_reference_is_not_adopted() {
        let appset = list_appset("fleet");
        let mut copy = Application::new("copied", appset.spec.template.spec.clone());
        copy.metadata.namespace = Some("ferriscd-system".to_owned());
        copy.metadata
            .labels
            .get_or_insert_with(BTreeMap::new)
            .insert(APPLICATIONSET_LABEL.to_owned(), "fleet".to_owned());
        assert!(matches!(
            ownership(&copy, &appset),
            Ownership::Foreign { .. }
        ));

        // The reverse: the owner reference alone is enough to be managed.
        let mut owned = copy.clone();
        owned
            .metadata
            .labels
            .get_or_insert_with(BTreeMap::new)
            .remove(APPLICATIONSET_LABEL);
        owned.metadata.owner_references = Some(vec![template::owner_reference(
            "fleet",
            &appset.metadata.uid.clone().unwrap_or_default(),
        )]);
        assert_eq!(ownership(&owned, &appset), Ownership::Managed);

        // A different namespace is never ours, however the metadata looks.
        let mut elsewhere = owned.clone();
        elsewhere.metadata.namespace = Some("payments".to_owned());
        assert!(matches!(
            ownership(&elsewhere, &appset),
            Ownership::Foreign { .. }
        ));
    }

    /// **Finding M6:** the same name is not the same object. An `ApplicationSet` deleted and
    /// re-created under the same name has a new uid, and the leftover `ownerReference` of the
    /// previous incarnation must be *stale*, not adopted — otherwise the new object would prune the
    /// old object's fleet.
    #[test]
    fn an_owner_reference_with_a_stale_uid_is_foreign() {
        let appset = list_appset("fleet");
        let mut inherited = Application::new("api", appset.spec.template.spec.clone());
        inherited.metadata.namespace = Some("ferriscd-system".to_owned());
        // Same apiVersion, kind, and name; the uid belongs to the deleted incarnation.
        inherited.metadata.owner_references = Some(vec![template::owner_reference(
            "fleet",
            "uid-from-a-deleted-incarnation",
        )]);
        let Ownership::Foreign { owner } = ownership(&inherited, &appset) else {
            panic!(
                "a stale uid must never be adopted, got {:?}",
                ownership(&inherited, &appset)
            );
        };
        assert!(
            owner.contains("uid-from-a-deleted-incarnation") && owner.contains("stale uid"),
            "the refusal must explain that the uid is stale: {owner}"
        );

        // The engine also refuses to plan anything for it: neither a rewrite nor a prune.
        let mut stale = inherited.clone();
        stale.metadata.uid = Some("uid-api".to_owned());
        let mut pruning = appset.clone();
        pruning.spec.sync_policy.prune = true;
        let empty = Generation::default();
        let plan = plan_reconcile(&pruning, &empty, &[stale]).expect("an empty generation plans");
        assert!(
            plan.prune.is_empty(),
            "an Application owned by a previous incarnation is never pruned: {:?}",
            plan.prune
        );

        // Conversely, an ApplicationSet without a uid (only unpersisted fixtures) falls back to the
        // name, which is all it can compare.
        let mut anonymous = appset.clone();
        anonymous.metadata.uid = None;
        assert_eq!(ownership(&inherited, &anonymous), Ownership::Managed);
    }

    #[test]
    fn deletion_orphans_by_default_and_deletes_only_when_opted_in() {
        let appset = list_appset("fleet");
        let mut owned = Application::new("generated", appset.spec.template.spec.clone());
        owned.metadata.namespace = Some("ferriscd-system".to_owned());
        owned.metadata.uid = Some("uid-generated".to_owned());
        owned.metadata.owner_references = Some(vec![template::owner_reference(
            "fleet",
            &appset.metadata.uid.clone().unwrap_or_default(),
        )]);
        let hand_written = {
            let mut app = Application::new("hand-written", appset.spec.template.spec.clone());
            app.metadata.namespace = Some("ferriscd-system".to_owned());
            app
        };

        let plan = plan_deletion(&appset, &[owned.clone(), hand_written.clone()]);
        assert!(plan.preserved);
        assert_eq!(
            plan.actions,
            vec![DeletionTarget {
                name: "generated".to_owned(),
                uid: Some("uid-generated".to_owned()),
                action: DeletionAction::Orphan,
            }],
            "deleting an ApplicationSet must never delete generated Applications by default"
        );

        let mut destructive = appset.clone();
        destructive.spec.sync_policy.preserve_resources_on_deletion = false;
        let plan = plan_deletion(&destructive, &[owned, hand_written]);
        assert!(!plan.preserved);
        assert_eq!(
            plan.actions,
            vec![DeletionTarget {
                name: "generated".to_owned(),
                uid: Some("uid-generated".to_owned()),
                action: DeletionAction::Delete,
            }],
            "even when opted in, an unmanaged Application is never touched — and the delete keeps \
             the uid it is allowed to remove"
        );
    }

    #[tokio::test]
    async fn a_two_hundred_application_matrix_is_deterministic_and_exactly_at_the_cap() {
        // A 20 x 10 matrix is exactly `MAX_GENERATED_APPS`. It must succeed (the cap is
        // inclusive), stay in memory, and produce the identical plan on every run.
        let appset = appset(
            "fleet",
            r#"
generators:
  - matrix:
      generators:
        - clusters: {}
        - list:
            elements:
              - path: apps/00
                basename: api-00
              - path: apps/01
                basename: api-01
              - path: apps/02
                basename: api-02
              - path: apps/03
                basename: api-03
              - path: apps/04
                basename: api-04
              - path: apps/05
                basename: api-05
              - path: apps/06
                basename: api-06
              - path: apps/07
                basename: api-07
              - path: apps/08
                basename: api-08
              - path: apps/09
                basename: api-09
template:
  metadata:
    name: "{{basename}}-{{cluster.name}}"
  spec:
    project: default
    source:
      git:
        repoURL: https://github.com/example/payments.git
        path: "{{path}}"
    destination:
      cluster: "{{cluster.name}}"
      namespace: payments
"#,
        );
        let clusters = FakeClusters(
            (0..20)
                .map(|index| ClusterRegistration::new(format!("c{index:02}"), BTreeMap::new()))
                .collect(),
        );
        let first = generate(&appset, &clusters, &FakeGit)
            .await
            .expect("exactly the cap is allowed");
        assert_eq!(first.len(), MAX_GENERATED_APPS);
        let second = generate(&appset, &clusters, &FakeGit)
            .await
            .expect("the same inputs generate the same fleet");
        assert_eq!(first, second);
        // Sorted by name, and every namespace/destination is fully substituted.
        let names = first.names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        assert!(
            first.applications().iter().all(|rendered| rendered
                .application
                .spec
                .destination
                .namespace
                == "payments")
        );
    }

    #[test]
    fn the_finalizer_and_label_constants_are_shared_with_the_crd() {
        assert_eq!(
            APPLICATIONSET_FINALIZER,
            "ferriscd.io/applicationset-cleanup"
        );
        assert_eq!(APPLICATIONSET_LABEL, "ferriscd.io/applicationset");
        assert_eq!(MAX_GENERATED_APPS, 200);
        assert_eq!(
            MAX_GENERATED_APPS,
            usize::try_from(ferriscd_crd::MAX_GENERATED_APPLICATIONS).expect("positive")
        );
    }

    #[test]
    fn status_reasons_are_bounded_and_stable() {
        let reasons = [
            ApplicationSetError::Spec(ApplicationSetSpecError::NoGenerator).reason(),
            ApplicationSetError::FanOutLimitExceeded {
                requested: 201,
                limit: 200,
                hard_limit: 200,
            }
            .reason(),
            ApplicationSetError::Template(TemplateError::UnterminatedPlaceholder).reason(),
            ApplicationSetError::DuplicateName {
                name: "a".to_owned(),
            }
            .reason(),
            ApplicationSetError::Conflict {
                name: "a".to_owned(),
                owner: "b".to_owned(),
            }
            .reason(),
            ApplicationSetError::Generator {
                generator: "git",
                message: "x".to_owned(),
                retryable: true,
            }
            .reason(),
            ApplicationSetError::ParameterFile {
                path: "p".to_owned(),
                message: "x".to_owned(),
            }
            .reason(),
            ApplicationSetError::WalkBudgetExceeded {
                limit: generators::MAX_GIT_WALK_ENTRIES,
            }
            .reason(),
        ];
        for reason in reasons {
            assert!(!reason.is_empty());
            assert!(reason.chars().count() <= 32, "{reason} is too long");
            assert!(
                reason
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase()),
                "{reason} must be CamelCase"
            );
        }
    }

    #[test]
    fn the_list_generator_type_is_reachable_through_the_engine() {
        // A small object-safety check: the planner takes `&dyn` sources, so both traits must stay
        // object-safe for the controller's adapters.
        let _: &dyn ClusterParamSource = &FakeClusters(Vec::new());
        let _: &dyn GitParameterSource = &FakeGit;
        let _ = ListGenerator::default();
        let _ = ClusterGenerator::default();
        let _ = ferriscd_crd::Condition::ready(
            ConditionStatus::True,
            "ApplicationsGenerated",
            "ok",
            Time(k8s_openapi::jiff::Timestamp::now()),
        );
        let _ = BTreeMap::<String, String>::new();
    }
}
