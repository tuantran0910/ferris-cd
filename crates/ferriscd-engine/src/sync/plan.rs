//! The pure `SyncPlan` builder: `DiffSummary` + policy ⇒ an explicit, auditable action list.
//!
//! Translating a diff pass into an explicit plan is what makes a sync *reviewable before it
//! writes anything*: every mutation FerrisCD may issue appears as a typed [`SyncAction`], every
//! refusal appears as a [`SyncAction::Skip`] carrying its reason, and the whole thing is built by
//! a pure function with no client, clock, or I/O — so the safety rails are unit-tested without a
//! cluster (T08.2).
//!
//! # Safety rails (never overridable by a single resource)
//!
//! ```text
//! foreign or unmanaged orphan          -> Skip (retained, never deleted)   trap T10
//! CustomResourceDefinition orphan      -> Skip unless syncOptions.pruneCRDs       H3
//! Namespace orphan                     -> Skip unless syncOptions.pruneNamespaces H3
//! ferriscd.io/prune: "false"           -> Skip (per-resource opt-out)
//! automated.prune: false               -> Skip (nothing is pruned at all)
//! gate decided Skip                    -> no Apply/Replace/Prune anywhere         M1
//! ```
//!
//! A desired resource whose live object belongs to another `Application` becomes
//! [`SyncAction::FailConflict`] rather than an apply: the object must never be adopted.
//!
//! `FailConflict` is **defence in depth**: the controller rejects a foreign owner for the whole
//! bundle before the plan is built (that rejection is terminal, reports `OutOfSync`, and stops the
//! pass before any mutation), so in the wired pipeline this step is unreachable. It stays because
//! the plan is a pure function with its own contract: a future caller that skips the pre-plan
//! ownership check must not get a silent `Apply` out of it.
//!
//! Prune protection for a `CustomResourceDefinition` has exactly one *enabling* switch:
//! `syncOptions.pruneCRDs`, per `Application`. There is no per-resource annotation that turns CRD
//! pruning on — `ferriscd.io/prune: "false"` is a **retain-only** opt-out that applies to any
//! resource (a CRD included) and can never widen what the switch refuses (T08.2 wording).
//!
//! # Ordering
//!
//! * applies follow [`crate::graph::order`] (twelve priority tiers, then `ResourceKey`),
//! * prunes follow the **exact reverse** of that order — see [`crate::graph::order::sort_prune_order`],
//! * `syncOptions.pruneLast` (default `true`) schedules prunes *after* every apply; with
//!   `pruneLast: false` they run first (reverse-tier deletion frees names and quota before the
//!   applies of that pass),
//! * `pre_create_namespace` is executed before the first step by the executor.
//!
//! # Replacement
//!
//! `ferriscd.io/sync-options: Replace=true` on a desired resource turns its step into
//! [`SyncAction::Replace`] (delete → wait for `404` → re-apply), which is the opt-in escape hatch
//! for immutable fields (T08.4). The immutable-field `422` itself is only observable at execution
//! time, so [`super::SyncAction::Apply`] keeps its `Force=false` default and the *executor* asks
//! the recovery module what to do.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ferriscd_crd::{SyncOptions, annotations};

use crate::diff::SkipReason;
use crate::diff::SyncDecision;
use crate::diff::types::{DiffStatus, ResourceDiff};
use crate::graph::order::{apply_cmp, is_crd_key, is_namespace_key};
use crate::manifest::types::{DesiredResource, ResourceKey};

/// A resource the previous inventory tracks but Git no longer declares, with the ownership
/// evidence the plan is allowed to see.
///
/// The plan deliberately does not receive a live object: it only needs the *verdict*, so the
/// safety rails are testable without constructing Kubernetes payloads (and no `Secret` document
/// can ever reach the planner).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanCandidate {
    /// Version-agnostic identity of the formerly managed object.
    pub key: ResourceKey,
    /// What the pass-level live read concluded about its ownership.
    pub ownership: OrphanOwnership,
    /// `ferriscd.io/prune: "false"` was present on the live object.
    pub prune_opted_out: bool,
}

impl OrphanCandidate {
    /// Builds a candidate from its parts.
    #[must_use]
    pub fn new(key: ResourceKey, ownership: OrphanOwnership, prune_opted_out: bool) -> Self {
        Self {
            key,
            ownership,
            prune_opted_out,
        }
    }

    /// A candidate whose live object is verifiably ours and does not opt out.
    #[must_use]
    pub fn owned(key: ResourceKey) -> Self {
        Self::new(key, OrphanOwnership::SelfOwned, false)
    }
}

/// Ownership verdict of an orphaned resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrphanOwnership {
    /// The live object carries exactly our `ferriscd.io/tracking-id`.
    SelfOwned,
    /// The live object carries a different `tracking-id` (another `Application`).
    Foreign(String),
    /// The live object carries no tracking annotation (created outside FerrisCD).
    Unmanaged,
    /// The pass confirmed the object (or its whole kind) is already gone (`404`/`410`,
    /// `NoMatchesForKind`). Confirmed absence counts as a confirmed prune.
    Gone,
    /// The pass never classified the key (defensive: never delete what was not looked at).
    NotFetched,
}

impl OrphanOwnership {
    /// Stable label used in logs and plan reasons.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SelfOwned => "OwnedBySelf",
            Self::Foreign(_) => "OwnedByForeign",
            Self::Unmanaged => "Unmanaged",
            Self::Gone => "Gone",
            Self::NotFetched => "NotFetched",
        }
    }
}

/// Why a [`SyncAction::Skip`] does nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanSkipReason {
    /// The sync gate refused to execute this pass (`automated: None`, `selfHeal: false` with an
    /// unchanged source, …). Nothing is applied *or* deleted.
    Gate(SkipReason),
    /// The diff already reported the resource `Synced`; `applyOutOfSyncOnly` keeps it untouched.
    AlreadySynced,
    /// The resource targets a `Namespace` this bundle declares, which does not exist yet (finding
    /// C3). It is not applied in this pass: the executor marks it pending and the requeue applies
    /// it, exactly one pass later (the namespace can only exist after this pass commits it).
    Deferred,
    /// The diff pass never classified the resource, so applying it blind is forbidden.
    Unclassified,
    /// `spec.syncPolicy.automated.prune` is `false`.
    PruneDisabled,
    /// The live object carries `ferriscd.io/prune: "false"`.
    PruneOptedOut,
    /// Safety rail (finding H3): `CustomResourceDefinition` pruning needs
    /// `syncOptions.pruneCRDs: true`.
    CrdPruneDisabled,
    /// Safety rail (finding H3): `Namespace` pruning needs `syncOptions.pruneNamespaces: true`.
    NamespacePruneDisabled,
    /// The live object belongs to another `Application` (trap T10): never pruned.
    ForeignOwner(String),
    /// The live object carries no tracking annotation: FerrisCD never deletes what it cannot
    /// prove it created.
    Unmanaged,
    /// The pass never looked at the key.
    NotFetched,
}

impl PlanSkipReason {
    /// Returns whether this skip *retains an orphan* (as opposed to skipping an apply).
    ///
    /// `status` reports retained orphans so a prune that silently does nothing is visible in
    /// `kubectl describe` (findings H1/H2) — this predicate is the one place that decides which
    /// skips count.
    #[must_use]
    pub fn retains_orphan(&self) -> bool {
        matches!(
            self,
            Self::PruneDisabled
                | Self::PruneOptedOut
                | Self::CrdPruneDisabled
                | Self::NamespacePruneDisabled
                | Self::ForeignOwner(_)
                | Self::Unmanaged
                | Self::NotFetched
        )
    }

    /// Stable label used in logs and the sync report.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gate(_) => "gate",
            Self::AlreadySynced => "alreadySynced",
            Self::Deferred => "deferred",
            Self::Unclassified => "unclassified",
            Self::PruneDisabled => "pruneDisabled",
            Self::PruneOptedOut => "pruneOptedOut",
            Self::CrdPruneDisabled => "crdPruneDisabled",
            Self::NamespacePruneDisabled => "namespacePruneDisabled",
            Self::ForeignOwner(_) => "foreignOwner",
            Self::Unmanaged => "unmanaged",
            Self::NotFetched => "notFetched",
        }
    }
}

impl fmt::Display for PlanSkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gate(reason) => write!(f, "not applied: {reason}"),
            Self::AlreadySynced => f.write_str("already synced"),
            Self::Deferred => f.write_str("deferred until the Namespace it targets exists"),
            Self::Unclassified => f.write_str("not classified by the diff pass"),
            Self::PruneDisabled => f.write_str("pruning is disabled"),
            Self::PruneOptedOut => f.write_str("live object carries ferriscd.io/prune=false"),
            Self::CrdPruneDisabled => {
                f.write_str("CustomResourceDefinition pruning needs syncOptions.pruneCRDs")
            }
            Self::NamespacePruneDisabled => {
                f.write_str("Namespace pruning needs syncOptions.pruneNamespaces")
            }
            Self::ForeignOwner(owner) => {
                write!(f, "owned by another Application ({owner})")
            }
            Self::Unmanaged => f.write_str("no ferriscd.io/tracking-id: not ours to delete"),
            Self::NotFetched => f.write_str("live state was never read"),
        }
    }
}

/// Why a resource may not be touched at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanConflict {
    /// The live object carries another `Application`'s `ferriscd.io/tracking-id`.
    ///
    /// Adopting it would let two `Application`s overwrite each other forever (trap T10), so the
    /// plan refuses up front instead of issuing an apply that cannot be safe.
    ForeignOwner {
        /// The foreign `tracking-id`, exactly as recorded on the live object.
        owner: String,
    },
}

impl fmt::Display for PlanConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForeignOwner { owner } => {
                write!(
                    f,
                    "the live object belongs to another Application ({owner})"
                )
            }
        }
    }
}

/// One planned action.
///
/// The variants are deliberately explicit: an executor never has to re-derive policy, and a test
/// can assert the exact action list a policy produces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncAction {
    /// Server-Side Apply the desired body (`force: false`).
    Apply {
        /// Resource to apply.
        key: ResourceKey,
    },
    /// Delete, wait until the object is gone (`404`), then Server-Side Apply it.
    ///
    /// Selected by `ferriscd.io/sync-options: Replace=true`; the immutable-field `422` case is
    /// upgraded to this at execution time by the recovery module.
    Replace {
        /// Resource to replace.
        key: ResourceKey,
    },
    /// Delete a previously managed resource after re-verifying ownership.
    Prune {
        /// Orphan to delete.
        key: ResourceKey,
    },
    /// Do nothing, for the stated reason.
    Skip {
        /// Resource left untouched.
        key: ResourceKey,
        /// Why nothing happens.
        reason: PlanSkipReason,
    },
    /// Refuse the resource; the pass fails with an actionable message instead of mutating it.
    FailConflict {
        /// Offending resource.
        key: ResourceKey,
        /// Why it cannot be synced.
        conflict: PlanConflict,
    },
}

impl SyncAction {
    /// The resource this action refers to.
    #[must_use]
    pub fn key(&self) -> &ResourceKey {
        match self {
            Self::Apply { key }
            | Self::Replace { key }
            | Self::Prune { key }
            | Self::Skip { key, .. }
            | Self::FailConflict { key, .. } => key,
        }
    }

    /// Returns whether this action mutates the cluster.
    #[must_use]
    pub fn mutates(&self) -> bool {
        matches!(
            self,
            Self::Apply { .. } | Self::Replace { .. } | Self::Prune { .. }
        )
    }

    /// Stable label used in logs and the sync report.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Apply { .. } => "apply",
            Self::Replace { .. } => "replace",
            Self::Prune { .. } => "prune",
            Self::Skip { .. } => "skip",
            Self::FailConflict { .. } => "failConflict",
        }
    }
}

/// Counts over a [`SyncPlan`], so a caller can report one line instead of iterating.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PlanSummary {
    /// `SyncAction::Apply` steps.
    pub apply: usize,
    /// `SyncAction::Replace` steps.
    pub replace: usize,
    /// `SyncAction::Prune` steps.
    pub prune: usize,
    /// `SyncAction::Skip` steps.
    pub skip: usize,
    /// `SyncAction::FailConflict` steps.
    pub fail_conflict: usize,
}

impl PlanSummary {
    /// Total number of steps.
    #[must_use]
    pub fn total(&self) -> usize {
        self.apply + self.replace + self.prune + self.skip + self.fail_conflict
    }

    /// Returns whether the plan mutates anything at all.
    #[must_use]
    pub fn mutates(&self) -> bool {
        self.apply + self.replace + self.prune > 0
    }
}

/// The explicit plan for one reconcile pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncPlan {
    /// Namespace the executor must create (Server-Side Apply) before the first step.
    ///
    /// Only set by `syncOptions.createNamespace` when the destination namespace is **not**
    /// declared in Git: a namespace that is in Git is managed like any other resource (tier 0,
    /// stamped with a tracking-id and therefore prunable when it leaves Git). A pre-created one
    /// is deliberately **unstamped**, so FerrisCD can never prune a namespace it only created
    /// for its own resources.
    pub pre_create_namespace: Option<String>,
    /// Actions in execution order.
    pub steps: Vec<SyncAction>,
}

impl SyncPlan {
    /// Builds the plan for one pass (pure: no client, no clock, no I/O).
    #[must_use]
    pub fn build(request: &PlanRequest<'_>) -> Self {
        let execute = request.decision.is_execute();
        let mut steps: Vec<SyncAction> = Vec::new();

        // --- desired resources, in apply order ------------------------------------------
        let mut ordered: Vec<&DesiredResource> = request.desired.iter().collect();
        ordered.sort_by(|left, right| apply_cmp(&left.key, &right.key));
        for resource in ordered {
            steps.push(desired_action(request, resource, execute));
        }

        // --- orphans, in reverse apply (prune) order ------------------------------------
        let mut prune_steps = orphan_actions(request, execute);
        // The orphan steps are built in apply order and reversed, so the prune order is the
        // exact reverse of the apply order instead of a second, drift-prone comparator.
        prune_steps.reverse();
        if request.options.prune_last {
            steps.append(&mut prune_steps);
        } else {
            let mut ordered_steps = prune_steps;
            ordered_steps.append(&mut steps);
            steps = ordered_steps;
        }

        Self {
            pre_create_namespace: pre_create_namespace(request, execute),
            steps,
        }
    }

    /// The namespace the executor must create first, if any.
    #[must_use]
    pub fn pre_create_namespace(&self) -> Option<&str> {
        self.pre_create_namespace.as_deref()
    }

    /// Counts by action kind.
    #[must_use]
    pub fn summary(&self) -> PlanSummary {
        let mut summary = PlanSummary::default();
        for step in &self.steps {
            match step {
                SyncAction::Apply { .. } => summary.apply += 1,
                SyncAction::Replace { .. } => summary.replace += 1,
                SyncAction::Prune { .. } => summary.prune += 1,
                SyncAction::Skip { .. } => summary.skip += 1,
                SyncAction::FailConflict { .. } => summary.fail_conflict += 1,
            }
        }
        summary
    }

    /// Returns whether executing this plan could change the cluster.
    #[must_use]
    pub fn mutates(&self) -> bool {
        self.pre_create_namespace.is_some() || self.summary().mutates()
    }

    /// Keys the diff verified are already in place **and** owned by this `Application`.
    ///
    /// These are recorded in `status.inventory` without an apply (finding C1): a wiped inventory
    /// must be repaired from live state, not by re-applying everything.
    #[must_use]
    pub fn synced_keys(&self) -> BTreeSet<ResourceKey> {
        self.steps
            .iter()
            .filter_map(|step| match step {
                SyncAction::Skip {
                    key,
                    reason: PlanSkipReason::AlreadySynced,
                } => Some(key.clone()),
                _ => None,
            })
            .collect()
    }

    /// Orphans this plan deliberately retains, with the reason (findings H1/H2).
    #[must_use]
    pub fn retained_orphans(&self) -> Vec<(&ResourceKey, &PlanSkipReason)> {
        self.steps
            .iter()
            .filter_map(|step| match step {
                SyncAction::Skip { key, reason } if reason.retains_orphan() => Some((key, reason)),
                _ => None,
            })
            .collect()
    }

    /// The first refusal in the plan, if any.
    #[must_use]
    pub fn first_conflict(&self) -> Option<(&ResourceKey, &PlanConflict)> {
        self.steps.iter().find_map(|step| match step {
            SyncAction::FailConflict { key, conflict } => Some((key, conflict)),
            _ => None,
        })
    }
}

/// Decides the action for one desired resource.
fn desired_action(
    request: &PlanRequest<'_>,
    resource: &DesiredResource,
    execute: bool,
) -> SyncAction {
    let key = resource.key.clone();

    if request.deferred.contains(&key) {
        return SyncAction::Skip {
            key,
            reason: PlanSkipReason::Deferred,
        };
    }

    let status = request.statuses.get(&key);
    if let Some(DiffStatus::OwnershipConflict { owner }) = status {
        // Trap T10: the object is another Application's. Refuse, do not adopt.
        return SyncAction::FailConflict {
            key,
            conflict: PlanConflict::ForeignOwner {
                owner: owner.clone(),
            },
        };
    }

    if !execute {
        // M1: a gate that decided to skip issues no mutation of any kind.
        return match status {
            Some(status) if status.is_synced() => SyncAction::Skip {
                key,
                reason: PlanSkipReason::AlreadySynced,
            },
            Some(_) => SyncAction::Skip {
                key,
                reason: PlanSkipReason::Gate(
                    request
                        .decision
                        .skip_reason()
                        .unwrap_or(SkipReason::AlreadySynced),
                ),
            },
            None => SyncAction::Skip {
                key,
                reason: PlanSkipReason::Unclassified,
            },
        };
    }

    if request.options.apply_out_of_sync_only {
        match status {
            // Never patch something the diff pass did not look at.
            None => {
                return SyncAction::Skip {
                    key,
                    reason: PlanSkipReason::Unclassified,
                };
            }
            Some(status) if !status.needs_apply() => {
                return SyncAction::Skip {
                    key,
                    reason: PlanSkipReason::AlreadySynced,
                };
            }
            Some(_) => {}
        }
    }

    if resource_requests_replace(resource) {
        SyncAction::Replace { key }
    } else {
        SyncAction::Apply { key }
    }
}

/// Decides the actions for the orphans (`prev_inventory \ desired`), in apply order.
fn orphan_actions(request: &PlanRequest<'_>, execute: bool) -> Vec<SyncAction> {
    let mut candidates: Vec<&OrphanCandidate> = request.orphans.iter().collect();
    candidates.sort_by(|left, right| apply_cmp(&left.key, &right.key));

    candidates
        .into_iter()
        .map(|candidate| prune_action(request, candidate, execute))
        .collect()
}

/// Decides the action for one orphan.
///
/// The safety rails are evaluated **before** the "may this pass execute" gate, so a pass that
/// deliberately applies nothing still reports the orphans it could never delete
/// (`ownedByForeign`, `unmanaged`, `pruneCRDs`, …) instead of silently reporting none. Only the
/// *decision to delete* depends on the gate (M1).
fn prune_action(
    request: &PlanRequest<'_>,
    candidate: &OrphanCandidate,
    execute: bool,
) -> SyncAction {
    let key = candidate.key.clone();
    let skip = |reason| SyncAction::Skip {
        key: key.clone(),
        reason,
    };

    if !request.prune_enabled {
        return skip(PlanSkipReason::PruneDisabled);
    }

    match &candidate.ownership {
        OrphanOwnership::NotFetched => return skip(PlanSkipReason::NotFetched),
        OrphanOwnership::Foreign(owner) => {
            return skip(PlanSkipReason::ForeignOwner(owner.clone()));
        }
        OrphanOwnership::Unmanaged => return skip(PlanSkipReason::Unmanaged),
        // A confirmed absence is a confirmed prune (the pruner re-checks before deleting), so it
        // takes the same rails as a live object: the *reason* the orphan must not be touched does
        // not depend on whether the object happens to still exist.
        OrphanOwnership::Gone | OrphanOwnership::SelfOwned => {}
    }
    if candidate.prune_opted_out {
        return skip(PlanSkipReason::PruneOptedOut);
    }
    // Finding H3: catastrophic CRD/Namespace auto-pruning is opt-in only.
    if is_crd_key(&key) && !request.options.prune_crds {
        return skip(PlanSkipReason::CrdPruneDisabled);
    }
    if is_namespace_key(&key) && !request.options.prune_namespaces {
        return skip(PlanSkipReason::NamespacePruneDisabled);
    }
    if !execute {
        // M1: pruning is part of "execute"; a skipped pass deletes nothing.
        return skip(PlanSkipReason::Gate(
            request
                .decision
                .skip_reason()
                .unwrap_or(SkipReason::AlreadySynced),
        ));
    }
    SyncAction::Prune { key }
}

/// Resolves `syncOptions.createNamespace` into the namespace to pre-create, if any.
fn pre_create_namespace(request: &PlanRequest<'_>, execute: bool) -> Option<String> {
    if !execute || !request.options.create_namespace {
        return None;
    }
    let namespace = request.destination_namespace.trim();
    if namespace.is_empty() {
        return None;
    }
    // A namespace declared in Git is applied and tracked like any other resource (it must stay
    // prunable when it leaves Git), so only an undeclared one is pre-created.
    let declared_in_git = request
        .desired
        .iter()
        .any(|resource| is_namespace_key(&resource.key) && resource.key.name == namespace);
    if declared_in_git {
        return None;
    }
    Some(namespace.to_owned())
}

/// Per-resource sync options parsed from `ferriscd.io/sync-options`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResourceSyncOptions {
    /// `Replace=true`: delete the live object (waiting for `404`) and re-apply it.
    pub replace: bool,
}

impl ResourceSyncOptions {
    /// Parses a `ferriscd.io/sync-options` value.
    ///
    /// The format is Argo CD's: a comma-separated list of `Key=Value` pairs. Keys and boolean
    /// values are matched case-insensitively and surrounding whitespace is ignored; unknown
    /// options are ignored (a newer CLI must not break an older controller).
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        let mut options = Self::default();
        for part in raw.split(',') {
            let Some((name, value)) = part.split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("replace") {
                options.replace = parse_bool(value);
            }
        }
        options
    }
}

/// Reads the per-resource sync options of a desired resource.
#[must_use]
pub fn resource_sync_options(resource: &DesiredResource) -> ResourceSyncOptions {
    resource
        .object
        .metadata
        .annotations
        .as_ref()
        .and_then(|map| map.get(annotations::SYNC_OPTIONS))
        .map(|raw| ResourceSyncOptions::parse(raw))
        .unwrap_or_default()
}

/// Returns whether `resource` opts into delete-and-recreate.
fn resource_requests_replace(resource: &DesiredResource) -> bool {
    resource_sync_options(resource).replace
}

/// Parses a boolean sync-option value (`true`/`1`, `false`/`0`; anything else is `false`).
fn parse_bool(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("true") || value == "1"
}

/// Everything the planner needs to know about one pass.
#[derive(Clone, Debug)]
pub struct PlanRequest<'a> {
    /// The sync-decision gate's verdict for this pass.
    pub decision: SyncDecision,
    /// The stamped, scope-normalized desired set (the exact slice the applier receives).
    pub desired: &'a [DesiredResource],
    /// Per-resource diff classification of this pass.
    pub statuses: &'a BTreeMap<ResourceKey, DiffStatus>,
    /// Keys deferred on a `Namespace` this bundle declares (and that does not exist yet).
    ///
    /// Only `DeferredPendingNamespace` keys ever reach this set: a custom resource deferred on a
    /// `CustomResourceDefinition` in the same bundle is planned as a normal `Apply`, because the
    /// executor establishes the CRD and refreshes discovery inside the same pass.
    pub deferred: &'a BTreeSet<ResourceKey>,
    /// Orphans (`prev_inventory \ desired`) with their ownership verdict.
    pub orphans: &'a [OrphanCandidate],
    /// Effective `spec.syncPolicy.syncOptions`.
    pub options: &'a SyncOptions,
    /// `spec.syncPolicy.automated.prune`.
    pub prune_enabled: bool,
    /// `spec.destination.namespace`.
    pub destination_namespace: &'a str,
}

impl<'a> PlanRequest<'a> {
    /// Builds a request from the engine-visible parts of a pass.
    #[must_use]
    pub fn new(
        decision: SyncDecision,
        desired: &'a [DesiredResource],
        statuses: &'a BTreeMap<ResourceKey, DiffStatus>,
        options: &'a SyncOptions,
        destination_namespace: &'a str,
    ) -> Self {
        Self {
            decision,
            desired,
            statuses,
            deferred: empty_keys(),
            orphans: &[],
            options,
            prune_enabled: false,
            destination_namespace,
        }
    }

    /// Attaches the deferred (pending `Namespace`) keys.
    #[must_use]
    pub fn with_deferred(mut self, deferred: &'a BTreeSet<ResourceKey>) -> Self {
        self.deferred = deferred;
        self
    }

    /// Attaches the orphan candidates.
    #[must_use]
    pub fn with_orphans(mut self, orphans: &'a [OrphanCandidate]) -> Self {
        self.orphans = orphans;
        self
    }

    /// Sets `automated.prune`.
    #[must_use]
    pub fn with_prune(mut self, prune_enabled: bool) -> Self {
        self.prune_enabled = prune_enabled;
        self
    }
}

/// A `'static` empty key set, so [`PlanRequest::new`] can default without allocating.
fn empty_keys() -> &'static BTreeSet<ResourceKey> {
    use std::sync::OnceLock;

    static EMPTY: OnceLock<BTreeSet<ResourceKey>> = OnceLock::new();
    EMPTY.get_or_init(BTreeSet::new)
}

/// Summarizes a diff pass into `(statuses, deferred)`.
///
/// The deferred set is *not* part of [`DiffStatus`] (a deferred resource is `Missing` for the
/// gate's purposes), so the caller passes the live-state verdict in separately; this helper only
/// indexes the statuses.
#[must_use]
pub fn statuses_by_key(diffs: &[ResourceDiff]) -> BTreeMap<ResourceKey, DiffStatus> {
    diffs
        .iter()
        .map(|diff| (diff.key().clone(), diff.status().clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::diff::SyncTrigger;
    use crate::manifest::types::GroupVersionKind;

    const NAMESPACE: &str = "payments";
    const CRD_NAME: &str = "widgets.example.com";

    fn resource(
        group: &str,
        kind: &str,
        namespace: Option<&str>,
        name: &str,
        annotations: Option<serde_json::Value>,
    ) -> DesiredResource {
        let api_version = if group.is_empty() {
            "v1".to_owned()
        } else {
            format!("{group}/v1")
        };
        let mut metadata = json!({ "name": name, "namespace": namespace });
        if let Some(annotations) = annotations {
            metadata["annotations"] = annotations;
        }
        let object = serde_json::from_value(json!({
            "apiVersion": api_version,
            "kind": kind,
            "metadata": metadata,
        }))
        .expect("valid DynamicObject");

        DesiredResource {
            key: ResourceKey::new(group, kind, namespace.map(str::to_owned), name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("parse gvk"),
            object,
            source_file: "fixture.yaml".to_owned(),
        }
    }

    fn key(group: &str, kind: &str, namespace: Option<&str>, name: &str) -> ResourceKey {
        ResourceKey::new(group, kind, namespace.map(str::to_owned), name)
    }

    fn configmap(name: &str) -> DesiredResource {
        resource("", "ConfigMap", Some(NAMESPACE), name, None)
    }

    fn deployment(name: &str) -> DesiredResource {
        resource("apps", "Deployment", Some(NAMESPACE), name, None)
    }

    fn crd(name: &str) -> DesiredResource {
        resource(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            name,
            None,
        )
    }

    fn widget(name: &str) -> DesiredResource {
        resource("example.com", "Widget", Some(NAMESPACE), name, None)
    }

    fn defaults() -> SyncOptions {
        SyncOptions::default()
    }

    fn statuses(pairs: &[(&DesiredResource, DiffStatus)]) -> BTreeMap<ResourceKey, DiffStatus> {
        pairs
            .iter()
            .map(|(resource, status)| (resource.key.clone(), status.clone()))
            .collect()
    }

    fn all_missing(desired: &[DesiredResource]) -> BTreeMap<ResourceKey, DiffStatus> {
        desired
            .iter()
            .map(|resource| (resource.key.clone(), DiffStatus::Missing))
            .collect()
    }

    fn execute() -> SyncDecision {
        SyncDecision::Execute(SyncTrigger::SourceChanged)
    }

    /// Builds a plan with the fixture defaults and returns it.
    fn build_plan<'a>(
        desired: &'a [DesiredResource],
        statuses: &'a BTreeMap<ResourceKey, DiffStatus>,
        options: &'a SyncOptions,
        orphans: &'a [OrphanCandidate],
        prune_enabled: bool,
    ) -> SyncPlan {
        SyncPlan::build(
            &PlanRequest::new(execute(), desired, statuses, options, NAMESPACE)
                .with_orphans(orphans)
                .with_prune(prune_enabled),
        )
    }

    fn actions(plan: &SyncPlan) -> Vec<(String, &'static str)> {
        plan.steps
            .iter()
            .map(|step| (step.key().canonical(), step.as_str()))
            .collect()
    }

    // ------------------------------------------------------------------
    // Happy path: applies in priority order
    // ------------------------------------------------------------------

    #[test]
    fn applies_follow_the_priority_order_and_custom_resources_come_after_crds() {
        // Reverse input order on purpose: the planner owns the ordering.
        let desired = vec![
            widget("one"),
            deployment("api"),
            configmap("settings"),
            crd(CRD_NAME),
        ];
        let statuses = all_missing(&desired);
        let options = defaults();
        let plan = build_plan(&desired, &statuses, &options, &[], false);

        assert_eq!(
            actions(&plan),
            vec![
                (
                    format!("apiextensions.k8s.io/CustomResourceDefinition//{CRD_NAME}"),
                    "apply"
                ),
                ("/ConfigMap/payments/settings".to_owned(), "apply"),
                ("apps/Deployment/payments/api".to_owned(), "apply"),
                ("example.com/Widget/payments/one".to_owned(), "apply"),
            ],
            "CRD first, workload before custom resource (trap T6)"
        );
        assert_eq!(plan.summary().apply, 4);
        assert!(plan.mutates());
        assert_eq!(plan.pre_create_namespace(), None);
    }

    #[test]
    fn apply_out_of_sync_only_skips_synced_resources_and_unclassified_keys() {
        let settings = configmap("settings");
        let api = deployment("api");
        let desired = vec![settings.clone(), api.clone()];
        let statuses = statuses(&[
            (&settings, DiffStatus::Synced),
            (&api, DiffStatus::OutOfSync),
        ]);
        let options = defaults();

        let default_plan = build_plan(&desired, &statuses, &options, &[], false);
        assert_eq!(
            actions(&default_plan),
            vec![
                ("/ConfigMap/payments/settings".to_owned(), "skip"),
                ("apps/Deployment/payments/api".to_owned(), "apply"),
            ],
            "applyOutOfSyncOnly (default true): only the drifting resource is applied"
        );
        assert_eq!(
            default_plan.synced_keys(),
            BTreeSet::from([settings.key.clone()]),
            "a synced resource is still recorded in the inventory (finding C1)"
        );

        // `applyOutOfSyncOnly: false` re-applies the whole desired set.
        let apply_all = SyncOptions {
            apply_out_of_sync_only: false,
            ..defaults()
        };
        let apply_all_plan = build_plan(&desired, &statuses, &apply_all, &[], false);
        assert_eq!(
            apply_all_plan
                .steps
                .iter()
                .filter(|step| step.mutates())
                .count(),
            2
        );

        // An unclassified resource is never patched blind, even with applyOutOfSyncOnly: false
        // it is applied only because the operator explicitly asked for a blanket apply.
        let unclassified = build_plan(&desired, &BTreeMap::new(), &defaults(), &[], false);
        assert!(
            unclassified.steps.iter().all(|step| !step.mutates()),
            "an unclassified resource must never be applied: {:?}",
            actions(&unclassified)
        );
        assert_eq!(
            unclassified
                .steps
                .iter()
                .filter(|step| matches!(
                    step,
                    SyncAction::Skip {
                        reason: PlanSkipReason::Unclassified,
                        ..
                    }
                ))
                .count(),
            2
        );
    }

    #[test]
    fn a_skipped_gate_plans_no_mutation_at_all() {
        let desired = vec![configmap("settings"), deployment("api")];
        let statuses = all_missing(&desired);
        let orphans = [OrphanCandidate::owned(key(
            "",
            "Secret",
            Some(NAMESPACE),
            "old",
        ))];
        let options = defaults();

        for reason in [
            SkipReason::AutomatedDisabled,
            SkipReason::SelfHealDisabled,
            SkipReason::AlreadySynced,
        ] {
            let request = PlanRequest::new(
                SyncDecision::Skip(reason),
                &desired,
                &statuses,
                &options,
                NAMESPACE,
            )
            .with_orphans(&orphans)
            .with_prune(true);
            let plan = SyncPlan::build(&request);

            assert!(!plan.mutates(), "a skipped pass must not mutate ({reason})");
            assert!(
                plan.steps.iter().all(|step| matches!(
                    step,
                    SyncAction::Skip {
                        reason: PlanSkipReason::Gate(_),
                        ..
                    }
                )),
                "{reason}: {:?}",
                actions(&plan)
            );
            assert_eq!(plan.summary().skip, 3);
            assert!(
                plan.retained_orphans().is_empty(),
                "no retention is reported for a gate skip"
            );
        }
    }

    #[test]
    fn a_synced_resource_is_reported_synced_even_on_a_skipped_pass() {
        let settings = configmap("settings");
        let api = deployment("api");
        let desired = vec![settings.clone(), api.clone()];
        let statuses = statuses(&[
            (&settings, DiffStatus::Synced),
            (&api, DiffStatus::OutOfSync),
        ]);
        let options = defaults();
        let plan = SyncPlan::build(&PlanRequest::new(
            SyncDecision::Skip(SkipReason::SelfHealDisabled),
            &desired,
            &statuses,
            &options,
            NAMESPACE,
        ));

        assert_eq!(
            plan.synced_keys(),
            BTreeSet::from([settings.key.clone()]),
            "finding C1: a skipped pass still repairs the inventory from live state"
        );
        assert!(
            matches!(
                &plan.steps[1],
                SyncAction::Skip {
                    reason: PlanSkipReason::Gate(SkipReason::SelfHealDisabled),
                    ..
                }
            ),
            "{:?}",
            actions(&plan)
        );
    }

    /// **Verification (finding C3):** a key the caller deferred is a `Skip`, never an `Apply`.
    ///
    /// The plan is key-agnostic; the wired pipeline only ever supplies
    /// `DeferredPendingNamespace` keys (a CRD-deferred CR is planned `Apply`).
    #[test]
    fn deferred_resources_are_skipped_not_applied() {
        let crd = crd(CRD_NAME);
        let widget = widget("one");
        let desired = vec![crd.clone(), widget.clone()];
        let statuses = all_missing(&desired);
        let deferred = BTreeSet::from([widget.key.clone()]);
        let options = defaults();

        let plan = SyncPlan::build(
            &PlanRequest::new(execute(), &desired, &statuses, &options, NAMESPACE)
                .with_deferred(&deferred),
        );
        assert_eq!(
            actions(&plan),
            vec![
                (
                    format!("apiextensions.k8s.io/CustomResourceDefinition//{CRD_NAME}"),
                    "apply"
                ),
                ("example.com/Widget/payments/one".to_owned(), "skip"),
            ]
        );
        assert!(
            matches!(
                &plan.steps[1],
                SyncAction::Skip {
                    reason: PlanSkipReason::Deferred,
                    ..
                }
            ),
            "the deferred key is skipped with its reason: {:?}",
            actions(&plan)
        );
    }

    #[test]
    fn an_ownership_conflict_fails_the_resource_instead_of_adopting_it() {
        let settings = configmap("settings");
        let desired = vec![settings.clone()];
        let statuses = statuses(&[(
            &settings,
            DiffStatus::OwnershipConflict {
                owner: "ferriscd-system/other:/ConfigMap:payments/settings".to_owned(),
            },
        )]);
        let options = defaults();

        let plan = build_plan(&desired, &statuses, &options, &[], false);
        assert_eq!(
            plan.first_conflict(),
            Some((
                &settings.key,
                &PlanConflict::ForeignOwner {
                    owner: "ferriscd-system/other:/ConfigMap:payments/settings".to_owned()
                }
            ))
        );
        assert!(!plan.mutates(), "a foreign object is never touched");
        assert!(
            plan.first_conflict()
                .unwrap()
                .1
                .to_string()
                .contains("another Application")
        );
    }

    // ------------------------------------------------------------------
    // Replace opt-in
    // ------------------------------------------------------------------

    #[test]
    fn a_replace_sync_option_turns_the_apply_into_a_replace() {
        let replaceable = resource(
            "",
            "ConfigMap",
            Some(NAMESPACE),
            "settings",
            Some(json!({ annotations::SYNC_OPTIONS: "Replace=true" })),
        );
        let plain = configmap("other");
        let desired = vec![replaceable.clone(), plain.clone()];
        let statuses = all_missing(&desired);
        let options = defaults();

        let plan = build_plan(&desired, &statuses, &options, &[], false);
        assert_eq!(
            actions(&plan),
            vec![
                ("/ConfigMap/payments/other".to_owned(), "apply"),
                ("/ConfigMap/payments/settings".to_owned(), "replace"),
            ]
        );
        assert_eq!(plan.summary().replace, 1);
        assert_eq!(plan.summary().apply, 1);
    }

    #[test]
    fn replace_sync_option_parsing_is_tolerant_and_case_insensitive() {
        for (raw, expected) in [
            ("Replace=true", true),
            ("replace=TRUE", true),
            ("Replace=1", true),
            (" Prune=false , Replace=true ", true),
            ("Replace=false", false),
            ("Replace=yes", false),
            ("Prune=true", false),
            ("garbage", false),
            ("", false),
        ] {
            assert_eq!(
                ResourceSyncOptions::parse(raw).replace,
                expected,
                "raw = {raw:?}"
            );
        }

        // A blank annotation is not an opt-in, and neither is an unrelated one.
        let blank = resource(
            "",
            "ConfigMap",
            Some(NAMESPACE),
            "settings",
            Some(json!({ annotations::SYNC_OPTIONS: "  " })),
        );
        assert!(!resource_requests_replace(&blank));
        let unrelated = resource(
            "",
            "ConfigMap",
            Some(NAMESPACE),
            "settings",
            Some(json!({ annotations::PRUNE: "false" })),
        );
        assert!(!resource_requests_replace(&unrelated));
    }

    // ------------------------------------------------------------------
    // Prune safety rails
    // ------------------------------------------------------------------

    #[test]
    fn an_owned_orphan_is_pruned_only_when_prune_is_enabled() {
        let orphan = OrphanCandidate::owned(key("", "ConfigMap", Some(NAMESPACE), "removed"));
        let options = defaults();
        let desired: Vec<DesiredResource> = Vec::new();

        let disabled = build_plan(
            &desired,
            &BTreeMap::new(),
            &options,
            std::slice::from_ref(&orphan),
            false,
        );
        assert_eq!(
            actions(&disabled),
            vec![("/ConfigMap/payments/removed".to_owned(), "skip")]
        );
        assert_eq!(
            disabled.retained_orphans(),
            vec![(&orphan.key, &PlanSkipReason::PruneDisabled)]
        );

        let enabled = build_plan(&desired, &BTreeMap::new(), &options, &[orphan], true);
        assert_eq!(
            actions(&enabled),
            vec![("/ConfigMap/payments/removed".to_owned(), "prune")]
        );
        assert!(enabled.retained_orphans().is_empty());
    }

    /// **Trap guard (T10):** a foreign or unmanaged orphan is never pruned.
    #[test]
    fn foreign_and_unmanaged_orphans_are_never_pruned() {
        let foreign = key("", "ConfigMap", Some(NAMESPACE), "foreign");
        let unmanaged = key("", "ConfigMap", Some(NAMESPACE), "unmanaged");
        let not_fetched = key("", "ConfigMap", Some(NAMESPACE), "unknown");
        let orphans = [
            OrphanCandidate::new(
                foreign.clone(),
                OrphanOwnership::Foreign("ferriscd-system/other".to_owned()),
                false,
            ),
            OrphanCandidate::new(unmanaged.clone(), OrphanOwnership::Unmanaged, false),
            OrphanCandidate::new(not_fetched.clone(), OrphanOwnership::NotFetched, false),
        ];
        let options = SyncOptions {
            prune_crds: true,
            prune_namespaces: true,
            ..defaults()
        };
        let plan = build_plan(&[], &BTreeMap::new(), &options, &orphans, true);

        assert!(
            plan.steps.iter().all(|step| !step.mutates()),
            "nothing may be deleted: {:?}",
            actions(&plan)
        );
        // Prune order is reverse apply order: same tier, so the names run backwards
        // (unmanaged > unknown > foreign).
        assert_eq!(
            plan.retained_orphans(),
            vec![
                (&unmanaged, &PlanSkipReason::Unmanaged),
                (&not_fetched, &PlanSkipReason::NotFetched),
                (
                    &foreign,
                    &PlanSkipReason::ForeignOwner("ferriscd-system/other".to_owned())
                ),
            ],
            "prune order is reverse apply order"
        );
        assert_eq!(plan.summary().prune, 0);
    }

    /// **Trap guard (H3):** a `CustomResourceDefinition` orphan survives unless
    /// `syncOptions.pruneCRDs: true`.
    #[test]
    fn crd_orphans_are_preserved_by_default() {
        let orphan = OrphanCandidate::owned(key(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            CRD_NAME,
        ));
        let options = defaults();
        let plan = build_plan(
            &[],
            &BTreeMap::new(),
            &options,
            std::slice::from_ref(&orphan),
            true,
        );

        assert_eq!(
            actions(&plan),
            vec![(
                format!("apiextensions.k8s.io/CustomResourceDefinition//{CRD_NAME}"),
                "skip"
            )],
            "a CRD orphan must be preserved by default"
        );
        assert_eq!(
            plan.retained_orphans(),
            vec![(&orphan.key, &PlanSkipReason::CrdPruneDisabled)]
        );

        let opted_in = SyncOptions {
            prune_crds: true,
            ..defaults()
        };
        let plan = build_plan(&[], &BTreeMap::new(), &opted_in, &[orphan], true);
        assert_eq!(plan.summary().prune, 1);
    }

    /// **Trap guard (H3):** a `Namespace` orphan survives unless
    /// `syncOptions.pruneNamespaces: true` — and `pruneCRDs` does not imply it.
    #[test]
    fn namespace_orphans_are_preserved_by_default() {
        let orphan = OrphanCandidate::owned(key("", "Namespace", None, "team-a"));
        let options = SyncOptions {
            prune_crds: true,
            ..defaults()
        };
        let plan = build_plan(
            &[],
            &BTreeMap::new(),
            &options,
            std::slice::from_ref(&orphan),
            true,
        );
        assert_eq!(
            plan.retained_orphans(),
            vec![(&orphan.key, &PlanSkipReason::NamespacePruneDisabled)],
            "pruneCRDs must not imply pruneNamespaces"
        );

        let opted_in = SyncOptions {
            prune_namespaces: true,
            ..defaults()
        };
        let plan = build_plan(&[], &BTreeMap::new(), &opted_in, &[orphan], true);
        assert_eq!(plan.summary().prune, 1);
    }

    #[test]
    fn a_resource_with_prune_false_is_never_pruned() {
        let key = key("", "ConfigMap", Some(NAMESPACE), "removed");
        let orphan = OrphanCandidate::new(key.clone(), OrphanOwnership::SelfOwned, true);
        let options = defaults();
        let plan = build_plan(&[], &BTreeMap::new(), &options, &[orphan], true);
        assert_eq!(
            actions(&plan),
            vec![("/ConfigMap/payments/removed".to_owned(), "skip")]
        );
        assert_eq!(
            plan.retained_orphans(),
            vec![(&key, &PlanSkipReason::PruneOptedOut)]
        );
    }

    #[test]
    fn a_confirmed_gone_orphan_is_pruned_without_a_delete_call() {
        // `404`/`410` at fetch time is a confirmed absence, which the pruner counts as pruned.
        let orphan = OrphanCandidate::new(
            key("", "ConfigMap", Some(NAMESPACE), "gone"),
            OrphanOwnership::Gone,
            false,
        );
        let options = defaults();
        let plan = build_plan(&[], &BTreeMap::new(), &options, &[orphan], true);
        assert_eq!(
            actions(&plan),
            vec![("/ConfigMap/payments/gone".to_owned(), "prune")]
        );
    }

    /// The safety rails do not depend on whether the object still exists: a `Gone`
    /// CRD/Namespace orphan is retained for exactly the same reason as a live one.
    #[test]
    fn a_gone_orphan_takes_the_same_safety_rails_as_a_live_one() {
        let crd = key(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            None,
            "widgets.example.com",
        );
        let namespace = key("", "Namespace", None, "team-a");
        let opted_out = key("", "ConfigMap", Some(NAMESPACE), "kept");
        let orphans = [
            OrphanCandidate::new(crd.clone(), OrphanOwnership::Gone, false),
            OrphanCandidate::new(namespace.clone(), OrphanOwnership::Gone, false),
            OrphanCandidate::new(opted_out.clone(), OrphanOwnership::Gone, true),
        ];
        let options = defaults();

        let plan = build_plan(&[], &BTreeMap::new(), &options, &orphans, true);
        assert_eq!(
            actions(&plan),
            vec![
                // Orphans are planned in reverse apply order, like a prune.
                ("/ConfigMap/payments/kept".to_owned(), "skip"),
                (
                    "apiextensions.k8s.io/CustomResourceDefinition//widgets.example.com".to_owned(),
                    "skip"
                ),
                ("/Namespace//team-a".to_owned(), "skip"),
            ],
            "a gone CRD/namespace/opted-out orphan must never be reported as pruned"
        );
        assert_eq!(
            plan.retained_orphans(),
            vec![
                (&opted_out, &PlanSkipReason::PruneOptedOut),
                (&crd, &PlanSkipReason::CrdPruneDisabled),
                (&namespace, &PlanSkipReason::NamespacePruneDisabled),
            ]
        );
        assert_eq!(plan.summary().prune, 0);
        assert!(!plan.mutates());
    }

    /// A pass the gate skipped still reports the orphans it may never delete: a silent skip would
    /// look exactly like "there was nothing to retain".
    #[test]
    fn a_gate_skipped_pass_still_reports_foreign_and_unmanaged_orphans() {
        let foreign = key("", "ConfigMap", Some(NAMESPACE), "foreign");
        let unmanaged = key("", "ConfigMap", Some(NAMESPACE), "unmanaged");
        let prunable = key("", "ConfigMap", Some(NAMESPACE), "prunable");
        let orphans = [
            OrphanCandidate::new(
                foreign.clone(),
                OrphanOwnership::Foreign("ferriscd-system/other".to_owned()),
                false,
            ),
            OrphanCandidate::new(unmanaged.clone(), OrphanOwnership::Unmanaged, false),
            OrphanCandidate::owned(prunable.clone()),
        ];
        let options = defaults();
        let statuses = BTreeMap::new();

        let plan = SyncPlan::build(
            &PlanRequest::new(
                SyncDecision::Skip(SkipReason::SelfHealDisabled),
                &[],
                &statuses,
                &options,
                NAMESPACE,
            )
            .with_orphans(&orphans)
            .with_prune(true),
        );

        assert_eq!(
            plan.retained_orphans(),
            vec![
                (&unmanaged, &PlanSkipReason::Unmanaged),
                (
                    &foreign,
                    &PlanSkipReason::ForeignOwner("ferriscd-system/other".to_owned())
                ),
            ],
            "the two orphans FerrisCD could never delete stay reported on a skipped pass"
        );
        // The prunable one is only waiting for an executing pass, so it is a gate skip.
        assert!(
            plan.steps.iter().any(|step| matches!(
                step,
                SyncAction::Skip {
                    key,
                    reason: PlanSkipReason::Gate(SkipReason::SelfHealDisabled),
                } if key == &prunable
            )),
            "a prunable orphan is a gate skip, not a retention"
        );
        assert_eq!(plan.summary().prune, 0, "a skipped pass plans no prune");
        assert!(!plan.mutates());
    }

    // ------------------------------------------------------------------
    // Ordering: applies then prunes, both deterministic
    // ------------------------------------------------------------------

    /// **Verification:** `pruneLast` (the default) schedules every prune after every apply.
    #[test]
    fn prune_last_schedules_prunes_after_all_applies() {
        let desired = vec![configmap("settings"), deployment("api")];
        let statuses = all_missing(&desired);
        let orphans = [
            OrphanCandidate::owned(key("", "ConfigMap", Some(NAMESPACE), "removed-a")),
            OrphanCandidate::owned(key("", "Service", Some(NAMESPACE), "removed-b")),
            OrphanCandidate::owned(key("", "Namespace", None, "team-a")),
        ];
        let options = SyncOptions {
            prune_last: true,
            prune_namespaces: true,
            ..defaults()
        };
        let plan = build_plan(&desired, &statuses, &options, &orphans, true);

        assert_eq!(
            actions(&plan),
            vec![
                ("/ConfigMap/payments/settings".to_owned(), "apply"),
                ("apps/Deployment/payments/api".to_owned(), "apply"),
                // Reverse apply order: Namespace (0) first -> pruned last.
                ("/Service/payments/removed-b".to_owned(), "prune"),
                ("/ConfigMap/payments/removed-a".to_owned(), "prune"),
                ("/Namespace//team-a".to_owned(), "prune"),
            ]
        );
        let first_prune = plan
            .steps
            .iter()
            .position(|step| matches!(step, SyncAction::Prune { .. }))
            .expect("prunes present");
        assert!(
            plan.steps[..first_prune]
                .iter()
                .all(|step| !matches!(step, SyncAction::Prune { .. })),
            "no prune may precede an apply when pruneLast is set"
        );
    }

    #[test]
    fn without_prune_last_prunes_run_first_in_reverse_order() {
        let desired = vec![configmap("settings")];
        let statuses = all_missing(&desired);
        let orphans = [OrphanCandidate::owned(key(
            "",
            "Service",
            Some(NAMESPACE),
            "removed",
        ))];
        let options = SyncOptions {
            prune_last: false,
            ..defaults()
        };
        let plan = build_plan(&desired, &statuses, &options, &orphans, true);
        assert_eq!(
            actions(&plan),
            vec![
                ("/Service/payments/removed".to_owned(), "prune"),
                ("/ConfigMap/payments/settings".to_owned(), "apply"),
            ]
        );
    }

    #[test]
    fn plan_ordering_is_deterministic_across_input_permutations() {
        let desired = vec![
            widget("one"),
            deployment("api"),
            configmap("settings"),
            crd(CRD_NAME),
            resource("", "Namespace", None, "team-a", None),
            resource("", "ServiceAccount", Some(NAMESPACE), "runner", None),
        ];
        let statuses = all_missing(&desired);
        let orphans = [
            OrphanCandidate::owned(key("", "ConfigMap", Some(NAMESPACE), "gone-b")),
            OrphanCandidate::owned(key("", "Secret", Some(NAMESPACE), "gone-a")),
        ];
        let options = SyncOptions {
            prune_namespaces: true,
            ..defaults()
        };

        let expected = actions(&build_plan(&desired, &statuses, &options, &orphans, true));

        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state >> 33
        };
        for round in 0..32 {
            let mut shuffled_desired = desired.clone();
            for index in (1..shuffled_desired.len()).rev() {
                let swap_with = (next() as usize) % (index + 1);
                shuffled_desired.swap(index, swap_with);
            }
            let mut shuffled_orphans = orphans.to_vec();
            shuffled_orphans.reverse();
            assert_eq!(
                actions(&build_plan(
                    &shuffled_desired,
                    &statuses,
                    &options,
                    &shuffled_orphans,
                    true
                )),
                expected,
                "round {round}"
            );
        }
    }

    // ------------------------------------------------------------------
    // createNamespace
    // ------------------------------------------------------------------

    #[test]
    fn create_namespace_pre_creates_an_undeclared_destination_namespace() {
        let desired = vec![configmap("settings")];
        let statuses = all_missing(&desired);

        let creating = SyncOptions {
            create_namespace: true,
            ..defaults()
        };
        let plan = build_plan(&desired, &statuses, &creating, &[], false);
        assert_eq!(plan.pre_create_namespace(), Some(NAMESPACE));
        assert!(plan.mutates());

        // Default: nothing is created implicitly.
        let plan = build_plan(&desired, &statuses, &defaults(), &[], false);
        assert_eq!(plan.pre_create_namespace(), None);

        // A skipped pass never creates a namespace either.
        let plan = SyncPlan::build(&PlanRequest::new(
            SyncDecision::Skip(SkipReason::AutomatedDisabled),
            &desired,
            &statuses,
            &creating,
            NAMESPACE,
        ));
        assert_eq!(plan.pre_create_namespace(), None);
        assert!(!plan.mutates());
    }

    #[test]
    fn a_namespace_declared_in_git_is_never_double_created() {
        // The Namespace is in Git: it is applied (tier 0) and stamped, so a pre-create would both
        // duplicate the apply and make the object look unmanaged.
        let declared = resource("", "Namespace", None, NAMESPACE, None);
        let desired = vec![declared.clone(), configmap("settings")];
        let statuses = all_missing(&desired);
        let creating = SyncOptions {
            create_namespace: true,
            ..defaults()
        };
        let plan = build_plan(&desired, &statuses, &creating, &[], false);
        assert_eq!(plan.pre_create_namespace(), None);
        assert_eq!(
            actions(&plan),
            vec![
                ("/Namespace//payments".to_owned(), "apply"),
                ("/ConfigMap/payments/settings".to_owned(), "apply"),
            ]
        );

        // A blank destination namespace can never be created.
        let plan = SyncPlan::build(&PlanRequest::new(
            execute(),
            &desired,
            &statuses,
            &creating,
            "   ",
        ));
        assert_eq!(plan.pre_create_namespace(), None);
    }

    // ------------------------------------------------------------------
    // Summary / helper surface
    // ------------------------------------------------------------------

    #[test]
    fn plan_summary_and_predicates_agree_with_the_steps() {
        let desired = vec![configmap("settings"), deployment("api")];
        let statuses = statuses(&[
            (&desired[0], DiffStatus::Synced),
            (&desired[1], DiffStatus::Missing),
        ]);
        let options = defaults();
        let plan = build_plan(&desired, &statuses, &options, &[], false);

        let summary = plan.summary();
        assert_eq!(summary.apply, 1);
        assert_eq!(summary.skip, 1);
        assert_eq!(summary.total(), plan.steps.len());
        assert!(summary.mutates());
        assert_eq!(
            summary,
            PlanSummary {
                apply: 1,
                skip: 1,
                ..PlanSummary::default()
            }
        );

        let empty = SyncPlan::default();
        assert_eq!(empty.summary(), PlanSummary::default());
        assert!(!empty.mutates());
        assert!(empty.steps.is_empty());
        assert_eq!(empty.pre_create_namespace(), None);

        // `statuses_by_key` indexes a diff pass by identity.
        let diff = crate::diff::types::ResourceDiff::missing(desired[1].key.clone());
        let indexed = statuses_by_key(&[diff]);
        assert_eq!(
            indexed.get(&desired[1].key),
            Some(&DiffStatus::Missing),
            "the planner consumes the diff's per-resource classification"
        );
    }

    #[test]
    fn skip_reasons_render_actionably() {
        for (reason, needle) in [
            (PlanSkipReason::AlreadySynced, "already synced"),
            (PlanSkipReason::CrdPruneDisabled, "syncOptions.pruneCRDs"),
            (
                PlanSkipReason::NamespacePruneDisabled,
                "syncOptions.pruneNamespaces",
            ),
            (PlanSkipReason::Unmanaged, "not ours to delete"),
            (
                PlanSkipReason::ForeignOwner("other/app".to_owned()),
                "another Application",
            ),
        ] {
            assert!(
                reason.to_string().contains(needle),
                "{reason} must mention {needle}"
            );
            assert!(!reason.as_str().is_empty());
        }
        assert_eq!(
            PlanSkipReason::Gate(SkipReason::SelfHealDisabled).as_str(),
            "gate"
        );
        assert_eq!(
            OrphanOwnership::Foreign("x".to_owned()).as_str(),
            "OwnedByForeign"
        );
        assert_eq!(
            SyncAction::Prune {
                key: configmap("x").key
            }
            .as_str(),
            "prune"
        );
    }
}
