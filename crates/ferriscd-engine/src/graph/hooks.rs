//! Lifecycle-hook parsing and partitioning (`T10.3`, parsing/partition half).
//!
//! A lifecycle hook is a rendered resource that FerrisCD **creates imperatively** around a sync
//! instead of applying it as part of the desired state: a `PreSync` database migration, a
//! `PostSync` smoke test, a `SyncFail` notification. Two invariants follow from that, and both are
//! enforced here, purely and without a cluster:
//!
//! 1. **A hook is never part of the permanent desired state.** [`partition`] removes every hook
//!    from the permanent set, so `inventory_from_desired` can never see one: a hook must not enter
//!    `status.inventory`, must not be pruned as an orphan when it disappears (the deletion policy
//!    owns its lifetime, not the pruner), and must not be reported as drift.
//! 2. **A hook's phases and deletion policy are parsed strictly.** A typo (`PostSync ` is fine,
//!    `Postsnc` is not) would otherwise silently mean "no hook", i.e. a smoke test that never runs
//!    or a migration that runs as a normal wave member — a much worse failure than a parse error.
//!
//! ```text
//! apiVersion: batch/v1
//! kind: Job
//! metadata:
//!   generateName: migrate-
//!   annotations:
//!     ferriscd.io/hook: PreSync
//!     ferriscd.io/hook-delete-policy: HookSucceeded
//! ```
//!
//! # Scope
//!
//! This module deliberately stops at *parsing and partitioning*. Executing a hook (create with
//! `generateName`, record the generated name in `status.operationState.activeHooks`, delete
//! according to the policy) belongs to the controller hook runner, which is wired once Phase 08's
//! `SyncExecutor` lands.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ferriscd_crd::annotations;
use ferriscd_crd::status::{ActiveHook, HealthStatus, SyncPhase};

use crate::graph::waves::{self, WavePlan, sync_wave};
use crate::graph::{annotation, tier};
use crate::inventory::{Inventory, inventory_from_desired};
use crate::manifest::{DesiredResource, ManifestError, ResourceKey};

/// Every hook phase, in execution order (`Skip` is not executed and sorts last).
pub const HOOK_PHASES: [HookPhase; 5] = [
    HookPhase::PreSync,
    HookPhase::Sync,
    HookPhase::PostSync,
    HookPhase::SyncFail,
    HookPhase::Skip,
];

/// Every hook deletion policy.
pub const HOOK_DELETE_POLICIES: [HookDeletePolicy; 3] = [
    HookDeletePolicy::BeforeHookCreation,
    HookDeletePolicy::HookSucceeded,
    HookDeletePolicy::HookFailed,
];

/// A lifecycle hook phase (`ferriscd.io/hook`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HookPhase {
    /// Runs before any wave is applied (migrations, credential seeding).
    PreSync,
    /// Runs alongside the `Sync` waves it shares a wave number with.
    Sync,
    /// Runs after every `Sync` wave is `Healthy` (smoke tests, notifications).
    PostSync,
    /// Runs only when the operation enters `SyncFail` (alerting, cleanup).
    SyncFail,
    /// Never applied at all: the resource is excluded from the sync entirely.
    ///
    /// `Skip` is a *hook annotation value*, not a phase: it is the documented way to keep a
    /// manifest in Git (so `kubectl apply` users still see it) while telling FerrisCD to ignore it.
    Skip,
}

impl HookPhase {
    /// The canonical wire/label form (`PreSync`, `Sync`, `PostSync`, `SyncFail`, `Skip`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreSync => "PreSync",
            Self::Sync => "Sync",
            Self::PostSync => "PostSync",
            Self::SyncFail => "SyncFail",
            Self::Skip => "Skip",
        }
    }

    /// Whether a hook in this phase is executed by the wave runner (every phase but `Skip`).
    #[must_use]
    pub const fn is_executed(self) -> bool {
        !matches!(self, Self::Skip)
    }

    /// The wire-level sync phase of an executed hook, or `None` for [`Self::Skip`].
    ///
    /// `HookPhase` is the annotation vocabulary (it includes `Skip`, which is not a phase), while
    /// [`SyncPhase`] is what `status.operationState.activeHooks[].phase` stores. This is the single
    /// mapping between the two, so the runner never re-implements it.
    #[must_use]
    pub const fn sync_phase(self) -> Option<SyncPhase> {
        match self {
            Self::PreSync => Some(SyncPhase::PreSync),
            Self::Sync => Some(SyncPhase::Sync),
            Self::PostSync => Some(SyncPhase::PostSync),
            Self::SyncFail => Some(SyncPhase::SyncFail),
            Self::Skip => None,
        }
    }
}

impl fmt::Display for HookPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// When a hook resource is deleted (`ferriscd.io/hook-delete-policy`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HookDeletePolicy {
    /// Delete a previous run of a named hook before re-creating it (the default).
    ///
    /// Without this, the second sync of a named hook fails with `409 AlreadyExists` forever.
    #[default]
    BeforeHookCreation,
    /// Delete the hook once it becomes `Healthy`.
    HookSucceeded,
    /// Delete the hook once it becomes `Degraded`.
    HookFailed,
}

impl HookDeletePolicy {
    /// The canonical label form (`BeforeHookCreation`, `HookSucceeded`, `HookFailed`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeHookCreation => "BeforeHookCreation",
            Self::HookSucceeded => "HookSucceeded",
            Self::HookFailed => "HookFailed",
        }
    }

    /// Whether this policy deletes the hook after it reached `Healthy`.
    #[must_use]
    pub const fn deletes_on_success(self) -> bool {
        matches!(self, Self::HookSucceeded)
    }

    /// Whether this policy deletes the hook after it reached `Degraded`.
    #[must_use]
    pub const fn deletes_on_failure(self) -> bool {
        matches!(self, Self::HookFailed)
    }
}

impl fmt::Display for HookDeletePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One parsed lifecycle hook.
#[derive(Clone, Debug)]
pub struct Hook {
    resource: DesiredResource,
    phases: Vec<HookPhase>,
    delete_policies: Vec<HookDeletePolicy>,
    wave: i32,
    id: String,
}

impl Hook {
    /// The hook's desired object (created imperatively by the runner, never applied as a wave).
    #[must_use]
    pub fn resource(&self) -> &DesiredResource {
        &self.resource
    }

    /// Version-agnostic identity of the hook resource.
    ///
    /// **Not** an identity for a `generateName` hook: its `metadata.name` is empty, so two
    /// `migrate-` Jobs of the same kind and namespace share this key. Use [`Self::id`] to track a
    /// hook across requeues.
    #[must_use]
    pub fn key(&self) -> &ResourceKey {
        &self.resource.key
    }

    /// Stable identity of the rendered hook: `<source file>#<ordinal>` (`migrate.yaml#0`).
    ///
    /// Group/Kind/Namespace/Name cannot identify a `generateName` hook (the name is generated by
    /// the API server, and two hooks of the same kind in the same namespace are different objects),
    /// so the runner keys `status.operationState.activeHooks` on this instead (findings H2).
    ///
    /// The ordinal counts the hooks of one source file in deterministic execution order
    /// (`wave`, then dependency tier, then [`ResourceKey`]), so it is reproducible for the same
    /// commit. Two `generateName` hooks of the *same* kind, namespace and wave inside one file tie
    /// on every sort key; their ordinals then follow the file's document order, which is still
    /// deterministic for a given commit.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The phases this hook runs in, in [`HOOK_PHASES`] order (`[Skip]` for a skipped resource).
    #[must_use]
    pub fn phases(&self) -> &[HookPhase] {
        &self.phases
    }

    /// The wave this hook is ordered in (its `ferriscd.io/sync-wave`, default `0`).
    #[must_use]
    pub fn wave(&self) -> i32 {
        self.wave
    }

    /// The deletion policies to enforce ([`HookDeletePolicy::BeforeHookCreation`] by default).
    #[must_use]
    pub fn delete_policies(&self) -> &[HookDeletePolicy] {
        &self.delete_policies
    }

    /// Whether this hook runs in `phase`.
    #[must_use]
    pub fn runs_in(&self, phase: HookPhase) -> bool {
        self.phases.contains(&phase)
    }

    /// Whether the resource is named by `metadata.name` (created with `Api::create`/`Api::patch`).
    #[must_use]
    pub fn is_named(&self) -> bool {
        !self.resource.key.name.is_empty()
    }

    /// Whether the resource relies on `metadata.generateName` (must be created with `Api::create`,
    /// and the generated live name must be recorded to avoid creating it twice — finding H2).
    #[must_use]
    pub fn uses_generate_name(&self) -> bool {
        self.resource.object.metadata.generate_name.is_some()
    }

    /// Builds the `status.operationState.activeHooks` record for one run of this hook.
    ///
    /// `generated_name` is the created object's `metadata.name`: for a `generateName` hook it is
    /// the name the API server generated, which is exactly what a later requeue must reuse instead
    /// of creating a second `Job` (finding H2). Returns `None` for [`HookPhase::Skip`], which is
    /// never created.
    #[must_use]
    pub fn active_hook(
        &self,
        phase: HookPhase,
        generated_name: impl Into<String>,
        health: HealthStatus,
    ) -> Option<ActiveHook> {
        phase.sync_phase().map(|sync_phase| {
            ActiveHook::new(
                sync_phase,
                self.wave,
                self.id.clone(),
                generated_name,
                health,
            )
        })
    }
}

/// The rendered bundle split into hooks, permanent resources, and skipped resources.
///
/// `permanent` is the only set that may reach the wave planner, `status.inventory`, the pruner, or
/// the drift diff. Hooks are created imperatively; skipped resources are ignored entirely.
///
/// # `Sync` hooks and the wave health gate (finding M-2)
///
/// A `ferriscd.io/hook: Sync` hook runs **inside** a `Sync` wave, next to the permanent resources
/// that share its wave number. The controller must therefore add it to that wave's *expected* health
/// set ([`crate::sync::StepHealth`]) before calling
/// [`SyncMachine::step`](crate::sync::SyncMachine::step): a wave whose `Job` is still `Progressing`
/// would otherwise be reported `Healthy` as soon as its permanent resources converge, and the next
/// wave would start while the inline migration is still running.
///
/// For a named hook the expected key is its [`Hook::key`]; for a `generateName` hook the key is not
/// known before creation, so the expected key must be built from the name recorded in
/// `status.operationState.activeHooks[].generatedName` (see [`Hook::active_hook`]).
#[derive(Clone, Debug, Default)]
pub struct HookPartition {
    hooks: Vec<Hook>,
    permanent: Vec<DesiredResource>,
    skipped: Vec<DesiredResource>,
}

impl HookPartition {
    /// Returns whether any resource is a hook.
    #[must_use]
    pub fn has_hooks(&self) -> bool {
        !self.hooks.is_empty()
    }

    /// Returns whether any hook runs in `phase`.
    ///
    /// Always `false` for [`HookPhase::Skip`]: a skipped resource is excluded from the sync and is
    /// reported by [`Self::skipped`] instead of being executed.
    #[must_use]
    pub fn has_phase(&self, phase: HookPhase) -> bool {
        phase.is_executed() && self.hooks.iter().any(|hook| hook.runs_in(phase))
    }

    /// Every parsed hook, ordered by `(wave, tier, key)`.
    #[must_use]
    pub fn hooks(&self) -> &[Hook] {
        &self.hooks
    }

    /// The hooks that run in `phase`, in execution order (`wave`, then tier, then key).
    ///
    /// A hook that lists several phases appears in each list, so a `PreSync,PostSync` notification
    /// runs in both places.
    #[must_use]
    pub fn hooks_in(&self, phase: HookPhase) -> Vec<&Hook> {
        self.hooks
            .iter()
            .filter(|hook| hook.runs_in(phase))
            .collect()
    }

    /// The permanent desired set (no hooks, no skipped resources).
    #[must_use]
    pub fn permanent(&self) -> &[DesiredResource] {
        &self.permanent
    }

    /// The resources excluded from the sync by `ferriscd.io/hook: Skip`.
    #[must_use]
    pub fn skipped(&self) -> &[DesiredResource] {
        &self.skipped
    }

    /// The inventory of the **permanent** set, which is what `status.inventory` must contain.
    ///
    /// This is the seam that keeps hooks out of the prune inventory: callers build the inventory
    /// from the partition instead of from the raw rendered bundle.
    #[must_use]
    pub fn permanent_inventory(&self) -> Inventory {
        inventory_from_desired(self.permanent.iter())
    }

    /// The wave plan of the **permanent** set (`T10.2` applied to `T10.3`'s output).
    ///
    /// This is the seam the controller should use: planning waves straight from the rendered
    /// bundle would apply a hook as a wave member, which puts it in `status.inventory` and makes it
    /// prunable — exactly what the hook partition exists to prevent.
    ///
    /// # Errors
    ///
    /// Propagates [`ManifestError::InvalidAnnotation`] for a permanent resource whose
    /// `ferriscd.io/sync-wave` is not a signed `i32`.
    pub fn wave_plan(&self) -> Result<WavePlan, ManifestError> {
        waves::partition(self.permanent.clone())
    }
}

/// Splits a rendered bundle into hooks, permanent resources, and skipped resources.
///
/// The permanent order is preserved as given (the wave planner re-sorts it); hooks are ordered by
/// `(wave, tier, key)` so the runner's creation order is deterministic.
///
/// # Errors
///
/// Returns a terminal [`ManifestError::InvalidAnnotation`] when `ferriscd.io/hook`,
/// `ferriscd.io/hook-delete-policy`, or `ferriscd.io/sync-wave` carries an unparseable value —
/// **including on a `ferriscd.io/hook: Skip` item**, whose annotations are validated before it is
/// partitioned out (finding M-9): a typo on a skipped resource would otherwise stay invisible until
/// the day the resource is un-skipped, and skipping must not silence a broken control annotation.
/// Missing annotations are not errors.
pub fn partition(resources: Vec<DesiredResource>) -> Result<HookPartition, ManifestError> {
    let mut hooks: Vec<Hook> = Vec::new();
    let mut permanent: Vec<DesiredResource> = Vec::new();
    let mut skipped: Vec<DesiredResource> = Vec::new();

    for resource in resources {
        let Some(raw) = annotation(&resource, annotations::HOOK) else {
            permanent.push(resource);
            continue;
        };

        // Every control annotation is validated before the item is partitioned anywhere, so a
        // skipped resource cannot hide a malformed `sync-wave` / `hook-delete-policy` (finding M-9).
        let phases = parse_phases(&resource, raw)?;
        let wave = sync_wave(&resource)?;
        let policies = delete_policies(&resource)?;

        if phases == [HookPhase::Skip] {
            skipped.push(resource);
            continue;
        }

        hooks.push(Hook {
            resource,
            phases,
            delete_policies: policies,
            wave,
            id: String::new(),
        });
    }

    // Deterministic execution order: wave, then dependency tier, then GKNN (same rule as waves).
    hooks.sort_by(|left, right| {
        left.wave
            .cmp(&right.wave)
            .then_with(|| tier(&left.resource).cmp(&tier(&right.resource)))
            .then_with(|| left.resource.key.cmp(&right.resource.key))
    });

    // Stable identity (`<source file>#<ordinal>`) assigned after the sort, so it depends only on
    // the rendered bundle and never on the order the renderer emitted the resources (finding H2).
    let mut ordinals: BTreeMap<String, usize> = BTreeMap::new();
    for hook in &mut hooks {
        let ordinal = ordinals
            .entry(hook.resource.source_file.clone())
            .or_insert(0);
        hook.id = format!("{}#{ordinal}", hook.resource.source_file);
        *ordinal = ordinal.saturating_add(1);
    }

    Ok(HookPartition {
        hooks,
        permanent,
        skipped,
    })
}

/// Parses the comma-separated `ferriscd.io/hook` value.
///
/// Tokens are matched case-insensitively and tolerate `-`/`_` separators (`pre-sync`), but an
/// empty token, an unknown token, or a blank annotation is a terminal error.
fn parse_phases(resource: &DesiredResource, raw: &str) -> Result<Vec<HookPhase>, ManifestError> {
    let tokens = split_tokens(resource, annotations::HOOK, raw)?;
    let mut phases: BTreeSet<HookPhase> = BTreeSet::new();
    for token in tokens {
        let phase = match normalize(token).as_str() {
            "presync" => HookPhase::PreSync,
            "sync" => HookPhase::Sync,
            "postsync" => HookPhase::PostSync,
            "syncfail" => HookPhase::SyncFail,
            "skip" => HookPhase::Skip,
            _ => {
                return Err(invalid(
                    resource,
                    format!(
                        "{} has an unknown hook phase {token:?}; expected one of {}",
                        annotations::HOOK,
                        HOOK_PHASES
                            .iter()
                            .map(|phase| phase.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        };
        phases.insert(phase);
    }

    // `BTreeSet` iterates in enum order, so a parsed hook always reports its phases in execution
    // order regardless of how the annotation was written.
    let phases: Vec<HookPhase> = phases.into_iter().collect();
    if phases.len() > 1 && phases.contains(&HookPhase::Skip) {
        // `Skip` means "never apply this", which cannot be combined with a phase that does apply
        // it: the ordering would silently depend on which token came first.
        return Err(invalid(
            resource,
            format!(
                "{} cannot combine Skip with another phase, got {raw:?}",
                annotations::HOOK
            ),
        ));
    }
    Ok(phases)
}

/// Parses `ferriscd.io/hook-delete-policy`, defaulting to [`HookDeletePolicy::BeforeHookCreation`].
fn delete_policies(resource: &DesiredResource) -> Result<Vec<HookDeletePolicy>, ManifestError> {
    let Some(raw) = annotation(resource, annotations::HOOK_DELETE_POLICY) else {
        return Ok(vec![HookDeletePolicy::default()]);
    };

    let tokens = split_tokens(resource, annotations::HOOK_DELETE_POLICY, raw)?;
    let mut policies: BTreeSet<HookDeletePolicy> = BTreeSet::new();
    for token in tokens {
        let policy = match normalize(token).as_str() {
            "beforehookcreation" => HookDeletePolicy::BeforeHookCreation,
            "hooksucceeded" => HookDeletePolicy::HookSucceeded,
            "hookfailed" => HookDeletePolicy::HookFailed,
            _ => {
                return Err(invalid(
                    resource,
                    format!(
                        "{} has an unknown policy {token:?}; expected one of {}",
                        annotations::HOOK_DELETE_POLICY,
                        HOOK_DELETE_POLICIES
                            .iter()
                            .map(|policy| policy.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ));
            }
        };
        policies.insert(policy);
    }
    Ok(policies.into_iter().collect())
}

/// Splits a comma-separated annotation value, rejecting blank values and empty tokens.
fn split_tokens<'a>(
    resource: &DesiredResource,
    key: &str,
    raw: &'a str,
) -> Result<Vec<&'a str>, ManifestError> {
    if raw.trim().is_empty() {
        return Err(invalid(
            resource,
            format!("{key} is blank; remove the annotation or list at least one value"),
        ));
    }

    let mut tokens = Vec::new();
    for token in raw.split(',') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return Err(invalid(
                resource,
                format!("{key} has an empty entry in {raw:?}; remove the stray comma"),
            ));
        }
        tokens.push(trimmed);
    }
    Ok(tokens)
}

/// Normalizes a token for matching: lowercase with `-`, `_` and whitespace removed.
fn normalize(token: &str) -> String {
    token
        .chars()
        .filter(|character| !matches!(character, '-' | '_' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Builds the terminal, actionable error for a malformed control annotation.
fn invalid(resource: &DesiredResource, message: String) -> ManifestError {
    ManifestError::InvalidAnnotation {
        file: resource.source_file.clone(),
        message: format!("{}: {message}", resource.key.canonical()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::graph::waves;
    use crate::manifest::types::GroupVersionKind;

    fn resource_with(
        kind: &str,
        name: &str,
        annotations: &[(&str, &str)],
        generate_name: Option<&str>,
    ) -> DesiredResource {
        let (group, version) = match kind {
            "Job" => ("batch", "v1"),
            "Deployment" => ("apps", "v1"),
            _ => ("", "v1"),
        };
        let api_version = if group.is_empty() {
            version.to_owned()
        } else {
            format!("{group}/{version}")
        };

        let mut metadata = json!({ "name": name, "namespace": "payments" });
        if let Some(generate_name) = generate_name {
            metadata["generateName"] = json!(generate_name);
        }
        if !annotations.is_empty() {
            let map: serde_json::Map<String, serde_json::Value> = annotations
                .iter()
                .map(|(key, value)| ((*key).to_owned(), json!(value)))
                .collect();
            metadata["annotations"] = serde_json::Value::Object(map);
        }

        DesiredResource {
            key: ResourceKey::new(group, kind, Some("payments".to_owned()), name),
            gvk: GroupVersionKind::parse(&api_version, kind).expect("valid apiVersion"),
            object: serde_json::from_value(json!({
                "apiVersion": api_version,
                "kind": kind,
                "metadata": metadata,
            }))
            .expect("valid DynamicObject"),
            source_file: format!("{}-{name}.yaml", kind.to_lowercase()),
        }
    }

    fn plain(kind: &str, name: &str) -> DesiredResource {
        resource_with(kind, name, &[], None)
    }

    fn hook(kind: &str, name: &str, phases: &str) -> DesiredResource {
        resource_with(kind, name, &[(annotations::HOOK, phases)], None)
    }

    fn keys(resources: &[DesiredResource]) -> Vec<String> {
        resources
            .iter()
            .map(|resource| resource.key.canonical())
            .collect()
    }

    fn hook_keys(hooks: &[&Hook]) -> Vec<String> {
        hooks.iter().map(|hook| hook.key().canonical()).collect()
    }

    #[test]
    fn a_bundle_without_hooks_partitions_entirely_into_permanent() {
        let resources = vec![plain("ConfigMap", "settings"), plain("Deployment", "api")];
        let partition = partition(resources).expect("valid bundle");

        assert!(!partition.has_hooks());
        assert!(partition.hooks().is_empty());
        assert!(partition.skipped().is_empty());
        assert_eq!(
            keys(partition.permanent()),
            vec![
                "/ConfigMap/payments/settings",
                "apps/Deployment/payments/api",
            ]
        );
        assert_eq!(partition.permanent_inventory().len(), 2);
    }

    #[test]
    fn hooks_are_partitioned_out_of_every_phase() {
        let resources = vec![
            hook("Job", "migrate", "PreSync"),
            hook("Deployment", "inline", "Sync"),
            hook("Job", "smoke", "PostSync"),
            hook("Job", "alert", "SyncFail"),
            plain("Deployment", "api"),
        ];
        let partition = partition(resources).expect("valid bundle");

        assert!(partition.has_hooks());
        assert_eq!(
            keys(partition.permanent()),
            vec!["apps/Deployment/payments/api"],
            "only the non-hook resource may stay permanent"
        );
        for phase in [
            HookPhase::PreSync,
            HookPhase::Sync,
            HookPhase::PostSync,
            HookPhase::SyncFail,
        ] {
            assert_eq!(
                hook_keys(&partition.hooks_in(phase)).len(),
                1,
                "phase {phase} must own exactly one hook"
            );
            assert!(partition.has_phase(phase), "phase {phase} must be reported");
        }
        assert!(!partition.has_phase(HookPhase::Skip));
        assert_eq!(partition.skipped().len(), 0);
    }

    /// T10.3 trap guard: applying the partition is what keeps hooks out of the prune inventory.
    #[test]
    fn hooks_never_enter_the_permanent_inventory() {
        let resources = vec![
            hook("Job", "migrate", "PreSync"),
            hook("Job", "smoke", "PostSync"),
            resource_with("Job", "ignored", &[(annotations::HOOK, "Skip")], None),
            plain("ConfigMap", "settings"),
        ];
        let partition = partition(resources).expect("valid bundle");
        let inventory = partition.permanent_inventory();

        assert_eq!(
            inventory
                .keys()
                .map(ResourceKey::canonical)
                .collect::<Vec<_>>(),
            vec!["/ConfigMap/payments/settings"]
        );
        for forbidden in [
            "batch/Job/payments/migrate",
            "batch/Job/payments/smoke",
            "batch/Job/payments/ignored",
        ] {
            assert!(
                !inventory.keys().any(|key| key.canonical() == forbidden),
                "{forbidden} must never be prunable inventory"
            );
        }

        // The wave plan is built from the permanent set only, so wave 0 contains no hook either.
        let plan = partition.wave_plan().expect("valid waves");
        assert_eq!(
            plan.keys()
                .iter()
                .map(ResourceKey::canonical)
                .collect::<Vec<_>>(),
            vec!["/ConfigMap/payments/settings".to_owned()],
            "hooks must never be applied as a wave member"
        );
        assert_eq!(
            plan.wave_numbers(),
            waves::partition(partition.permanent().to_vec())
                .expect("valid waves")
                .wave_numbers(),
            "wave_plan() is the composition seam for T10.2"
        );
    }

    #[test]
    fn a_skip_annotated_resource_is_excluded_from_hooks_and_permanent() {
        let partition = partition(vec![
            resource_with("Job", "ignored", &[(annotations::HOOK, "Skip")], None),
            plain("ConfigMap", "settings"),
        ])
        .expect("valid bundle");

        assert_eq!(partition.skipped().len(), 1);
        assert_eq!(
            keys(partition.skipped()),
            vec!["batch/Job/payments/ignored"]
        );
        assert!(
            partition.hooks().is_empty(),
            "Skip is not an executable hook"
        );
        assert_eq!(
            keys(partition.permanent()),
            vec!["/ConfigMap/payments/settings"]
        );
    }

    #[test]
    fn hook_phases_parse_case_and_separator_insensitively_in_execution_order() {
        let partition = partition(vec![resource_with(
            "Job",
            "notify",
            &[(annotations::HOOK, "post-sync, PRE_SYNC")],
            None,
        )])
        .expect("valid bundle");

        let hook = &partition.hooks()[0];
        assert_eq!(
            hook.phases(),
            &[HookPhase::PreSync, HookPhase::PostSync],
            "phases are normalized and reported in execution order"
        );
        assert!(hook.runs_in(HookPhase::PreSync));
        assert!(hook.runs_in(HookPhase::PostSync));
        assert!(!hook.runs_in(HookPhase::SyncFail));
        assert_eq!(hook_keys(&partition.hooks_in(HookPhase::PostSync)).len(), 1);
    }

    #[test]
    fn every_valid_phase_and_alias_is_accepted() {
        for (annotation_value, expected) in [
            ("PreSync", HookPhase::PreSync),
            ("presync", HookPhase::PreSync),
            ("pre-sync", HookPhase::PreSync),
            (" Sync ", HookPhase::Sync),
            ("PostSync", HookPhase::PostSync),
            ("SyncFail", HookPhase::SyncFail),
            ("sync-fail", HookPhase::SyncFail),
            ("Skip", HookPhase::Skip),
            ("SKIP", HookPhase::Skip),
        ] {
            let partition = partition(vec![resource_with(
                "Job",
                "one",
                &[(annotations::HOOK, annotation_value)],
                None,
            )])
            .expect("valid hook");
            let observed: Vec<HookPhase> = if expected == HookPhase::Skip {
                assert!(partition.hooks().is_empty());
                partition
                    .skipped()
                    .iter()
                    .map(|_| HookPhase::Skip)
                    .collect()
            } else {
                partition.hooks()[0].phases().to_vec()
            };
            assert_eq!(observed, vec![expected], "annotation {annotation_value:?}");
        }
    }

    #[test]
    fn blank_and_invalid_hook_values_are_terminal_errors() {
        for value in [
            "",
            "   ",
            "Pre",
            "Postsnc",
            "PreSync,",
            ",PreSync",
            "PreSync,,PostSync",
            "SyncFail1",
            "Skip,PreSync",
            "PostSync,Skip",
        ] {
            let bad = resource_with("Job", "migrate", &[(annotations::HOOK, value)], None);
            let err = partition(vec![bad]).expect_err("invalid hook value must be rejected");
            assert!(
                matches!(err, ManifestError::InvalidAnnotation { .. }),
                "unexpected variant for {value:?}: {err:?}"
            );
            assert!(!err.is_retryable(), "a malformed annotation is terminal");

            let text = err.to_string();
            assert!(
                text.contains("ferriscd.io/hook"),
                "the error must name the annotation: {text}"
            );
            assert!(
                text.contains("/Job/payments/migrate"),
                "the error must name the resource: {text}"
            );
            assert!(
                text.contains("job-migrate.yaml"),
                "the error must name the file: {text}"
            );
        }
    }

    #[test]
    fn delete_policies_default_to_before_hook_creation() {
        let partition = partition(vec![hook("Job", "migrate", "PreSync")]).expect("valid hook");
        assert_eq!(
            partition.hooks()[0].delete_policies(),
            &[HookDeletePolicy::BeforeHookCreation],
            "a named hook must be re-createable on the next sync without 409 AlreadyExists"
        );
        assert_eq!(
            HookDeletePolicy::default(),
            HookDeletePolicy::BeforeHookCreation
        );
    }

    #[test]
    fn delete_policies_parse_every_documented_spelling() {
        for (annotation_value, expected) in [
            ("HookSucceeded", HookDeletePolicy::HookSucceeded),
            ("hook-succeeded", HookDeletePolicy::HookSucceeded),
            ("HOOK_FAILED", HookDeletePolicy::HookFailed),
            ("before-hook-creation", HookDeletePolicy::BeforeHookCreation),
        ] {
            let partition = partition(vec![resource_with(
                "Job",
                "migrate",
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::HOOK_DELETE_POLICY, annotation_value),
                ],
                None,
            )])
            .expect("valid hook");
            assert_eq!(
                partition.hooks()[0].delete_policies(),
                &[expected],
                "annotation {annotation_value:?}"
            );
        }

        // Several policies may be combined, and the result is deterministic.
        let partition = partition(vec![resource_with(
            "Job",
            "migrate",
            &[
                (annotations::HOOK, "PostSync"),
                (annotations::HOOK_DELETE_POLICY, "HookFailed, HookSucceeded"),
            ],
            None,
        )])
        .expect("valid hook");
        assert_eq!(
            partition.hooks()[0].delete_policies(),
            &[
                HookDeletePolicy::HookSucceeded,
                HookDeletePolicy::HookFailed
            ]
        );
        assert!(HookDeletePolicy::HookSucceeded.deletes_on_success());
        assert!(!HookDeletePolicy::HookSucceeded.deletes_on_failure());
        assert!(HookDeletePolicy::HookFailed.deletes_on_failure());
    }

    #[test]
    fn invalid_delete_policies_are_terminal_errors() {
        for value in ["", "  ", "HookSucceed", "always", "HookSucceeded,"] {
            let err = partition(vec![resource_with(
                "Job",
                "migrate",
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::HOOK_DELETE_POLICY, value),
                ],
                None,
            )])
            .expect_err("invalid delete policy must be rejected");
            assert!(!err.is_retryable());
            assert!(
                err.to_string().contains("ferriscd.io/hook-delete-policy"),
                "{err}"
            );
        }
    }

    #[test]
    fn hooks_keep_their_wave_and_sort_by_wave_tier_and_key() {
        let partition = partition(vec![
            resource_with(
                "Job",
                "smoke",
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::SYNC_WAVE, "1"),
                ],
                None,
            ),
            resource_with(
                "Deployment",
                "inline",
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::SYNC_WAVE, "0"),
                ],
                None,
            ),
            resource_with(
                "Job",
                "migrate",
                &[
                    (annotations::HOOK, "PreSync"),
                    (annotations::SYNC_WAVE, "-1"),
                ],
                None,
            ),
        ])
        .expect("valid hooks");

        assert_eq!(
            partition
                .hooks_in(HookPhase::PreSync)
                .iter()
                .map(|hook| (hook.wave(), hook.key().canonical()))
                .collect::<Vec<_>>(),
            vec![
                (-1, "batch/Job/payments/migrate".to_owned()),
                (0, "apps/Deployment/payments/inline".to_owned()),
                (1, "batch/Job/payments/smoke".to_owned()),
            ],
            "hooks run in wave order; T10.3 requires PreSync hooks sorted by wave"
        );
    }

    #[test]
    fn an_invalid_wave_on_a_hook_is_reported() {
        let err = partition(vec![resource_with(
            "Job",
            "migrate",
            &[
                (annotations::HOOK, "PreSync"),
                (annotations::SYNC_WAVE, "soon"),
            ],
            None,
        )])
        .expect_err("invalid hook wave must be rejected");
        assert!(err.to_string().contains("ferriscd.io/sync-wave"), "{err}");
        assert!(!err.is_retryable());
    }

    #[test]
    fn generate_name_hooks_are_detected() {
        let partition = partition(vec![
            resource_with(
                "Job",
                "",
                &[(annotations::HOOK, "PreSync")],
                Some("migrate-"),
            ),
            hook("Job", "named", "PreSync"),
        ])
        .expect("valid hooks");

        let generate_name_hook = partition
            .hooks()
            .iter()
            .find(|hook| hook.key().name.is_empty())
            .expect("generateName hook present");
        assert!(generate_name_hook.uses_generate_name());
        assert!(!generate_name_hook.is_named());

        let named = partition
            .hooks()
            .iter()
            .find(|hook| hook.key().name == "named")
            .expect("named hook present");
        assert!(named.is_named());
        assert!(!named.uses_generate_name());
    }

    #[test]
    fn has_phase_reports_only_executable_phases() {
        let partition = partition(vec![hook("Job", "migrate", "PreSync")]).expect("valid hook");
        assert!(partition.has_phase(HookPhase::PreSync));
        for phase in [
            HookPhase::Sync,
            HookPhase::PostSync,
            HookPhase::SyncFail,
            HookPhase::Skip,
        ] {
            assert!(!partition.has_phase(phase), "phase {phase}");
            assert!(partition.hooks_in(phase).is_empty(), "phase {phase}");
        }
    }

    #[test]
    fn hook_and_permanent_order_is_deterministic_across_input_orders() {
        // Building the same bundle in two different orders must produce the same hook order.
        let first = vec![
            hook("Job", "b", "PostSync"),
            hook("Job", "a", "PostSync"),
            plain("ConfigMap", "z"),
        ];
        let mut second = first.clone();
        second.reverse();

        let first_partition = partition(first).expect("valid bundle");
        let second_partition = partition(second).expect("valid bundle");
        assert_eq!(
            first_partition
                .hooks()
                .iter()
                .map(|hook| hook.key().canonical())
                .collect::<Vec<_>>(),
            second_partition
                .hooks()
                .iter()
                .map(|hook| hook.key().canonical())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            keys(first_partition.permanent()),
            keys(second_partition.permanent())
        );
    }

    fn in_file(mut resource: DesiredResource, source_file: &str) -> DesiredResource {
        resource.source_file = source_file.to_owned();
        resource
    }

    fn hook_ids(partition: &HookPartition) -> Vec<String> {
        partition
            .hooks()
            .iter()
            .map(|hook| hook.id().to_owned())
            .collect()
    }

    /// Finding H2: two `generateName` hooks of the same kind and namespace are distinct objects, so
    /// their GKNN key cannot track them. `<source file>#<ordinal>` must be per-hook and per-file.
    #[test]
    fn generate_name_hooks_get_distinct_per_file_ids() {
        let partition = partition(vec![
            in_file(
                resource_with(
                    "Job",
                    "migrate-one",
                    &[(annotations::HOOK, "PreSync")],
                    None,
                ),
                "migrations.yaml",
            ),
            in_file(
                resource_with(
                    "Job",
                    "",
                    &[
                        (annotations::HOOK, "PreSync"),
                        (annotations::SYNC_WAVE, "-1"),
                    ],
                    Some("migrate-"),
                ),
                "migrations.yaml",
            ),
            in_file(
                resource_with(
                    "Job",
                    "",
                    &[(annotations::HOOK, "PreSync")],
                    Some("migrate-"),
                ),
                "migrations.yaml",
            ),
            in_file(hook("Job", "smoke", "PostSync"), "hooks.yaml"),
        ])
        .expect("valid hooks");

        // Execution order is wave, then tier, then key (`""` sorts before `migrate-one`), and the
        // ordinal counts the hooks of one source file in that order.
        assert_eq!(
            hook_ids(&partition),
            vec![
                "migrations.yaml#0".to_owned(),
                "migrations.yaml#1".to_owned(),
                "migrations.yaml#2".to_owned(),
                "hooks.yaml#0".to_owned(),
            ]
        );
        assert_eq!(partition.hooks()[0].wave(), -1);
        assert_eq!(
            partition
                .hooks()
                .iter()
                .filter(|hook| hook.uses_generate_name())
                .count(),
            2,
            "the two generateName hooks share an empty GKNN name"
        );
        let mut names: Vec<&str> = partition
            .hooks()
            .iter()
            .filter(|hook| hook.uses_generate_name())
            .map(|hook| hook.key().name.as_str())
            .collect();
        names.dedup();
        assert_eq!(names, vec![""], "their keys are indistinguishable");
    }

    #[test]
    fn hook_ids_do_not_depend_on_the_rendered_input_order() {
        let bundle = vec![
            in_file(hook("Job", "smoke", "PostSync"), "hooks.yaml"),
            in_file(
                resource_with(
                    "Job",
                    "",
                    &[
                        (annotations::HOOK, "PreSync"),
                        (annotations::SYNC_WAVE, "-1"),
                    ],
                    Some("migrate-"),
                ),
                "migrations.yaml",
            ),
            plain("ConfigMap", "settings"),
        ];
        let expected = hook_ids(&partition(bundle.clone()).expect("valid bundle"));

        for offset in 0..bundle.len() {
            let mut rotated = bundle.clone();
            rotated.rotate_left(offset);
            assert_eq!(
                hook_ids(&partition(rotated).expect("valid bundle")),
                expected,
                "rotation {offset} must not renumber the hooks"
            );
        }

        let mut reversed = bundle;
        reversed.reverse();
        assert_eq!(
            hook_ids(&partition(reversed).expect("valid bundle")),
            expected
        );
    }

    /// Two identical `generateName` hooks in one file tie on every sort key; the ordinal then
    /// follows the document order, so the id set is still stable for a given commit.
    #[test]
    fn tied_generate_name_hooks_still_produce_the_same_id_set() {
        let first = resource_with(
            "Job",
            "",
            &[(annotations::HOOK, "PreSync")],
            Some("migrate-"),
        );
        let second = resource_with(
            "Job",
            "",
            &[(annotations::HOOK, "PreSync")],
            Some("worker-"),
        );
        let bundle = vec![
            in_file(first, "migrations.yaml"),
            in_file(second, "migrations.yaml"),
        ];

        let forward = hook_ids(&partition(bundle.clone()).expect("valid bundle"));
        let mut reversed_bundle = bundle;
        reversed_bundle.reverse();
        let reversed = hook_ids(&partition(reversed_bundle).expect("valid bundle"));
        assert_eq!(forward, reversed);
        assert_eq!(
            forward,
            vec![
                "migrations.yaml#0".to_owned(),
                "migrations.yaml#1".to_owned()
            ]
        );
    }

    /// Finding H2: the tracking record the runner persists must carry the stable id, the wave, the
    /// wire phase, and the created (generated) name — and never exist for a `Skip` item.
    #[test]
    fn active_hook_records_carry_the_stable_id_and_the_generated_name() {
        let partition = partition(vec![
            in_file(
                resource_with(
                    "Job",
                    "",
                    &[(annotations::HOOK, "PreSync")],
                    Some("migrate-"),
                ),
                "migrations.yaml",
            ),
            resource_with("Job", "ignored", &[(annotations::HOOK, "Skip")], None),
        ])
        .expect("valid hooks");

        let hook = &partition.hooks()[0];
        let active = hook
            .active_hook(
                HookPhase::PreSync,
                "migrate-7f9c2",
                HealthStatus::Progressing,
            )
            .expect("an executed phase yields a tracking record");
        assert_eq!(active.hook_id, "migrations.yaml#0");
        assert_eq!(active.generated_name, "migrate-7f9c2");
        assert_eq!(active.phase, SyncPhase::PreSync);
        assert_eq!(active.wave, 0);
        assert_eq!(active.health, HealthStatus::Progressing);
        assert!(!active.is_healthy());

        // The record round-trips through `/status` unchanged.
        let json = serde_json::to_value(&active).expect("record must serialize");
        assert_eq!(json["hookId"], serde_json::json!("migrations.yaml#0"));
        assert_eq!(
            serde_json::from_value::<ActiveHook>(json).expect("record must deserialize"),
            active
        );

        // Every executed phase maps onto the wire phase; `Skip` has none.
        for (phase, expected) in [
            (HookPhase::PreSync, SyncPhase::PreSync),
            (HookPhase::Sync, SyncPhase::Sync),
            (HookPhase::PostSync, SyncPhase::PostSync),
            (HookPhase::SyncFail, SyncPhase::SyncFail),
        ] {
            assert_eq!(phase.sync_phase(), Some(expected));
            assert!(
                hook.active_hook(phase, "name", HealthStatus::Healthy)
                    .is_some_and(|record| record.is_healthy())
            );
        }
        assert_eq!(HookPhase::Skip.sync_phase(), None);
        assert!(
            hook.active_hook(HookPhase::Skip, "name", HealthStatus::Healthy)
                .is_none()
        );
    }

    /// Finding M-9: skipping a resource must not silence a malformed control annotation.
    #[test]
    fn skip_items_are_validated_before_they_are_partitioned_out() {
        for (annotation, value, expected) in [
            (annotations::SYNC_WAVE, "soon", "ferriscd.io/sync-wave"),
            (
                annotations::HOOK_DELETE_POLICY,
                "always",
                "ferriscd.io/hook-delete-policy",
            ),
            (annotations::SYNC_WAVE, "", "ferriscd.io/sync-wave"),
        ] {
            let bad = resource_with(
                "Job",
                "ignored",
                &[(annotations::HOOK, "Skip"), (annotation, value)],
                None,
            );
            let err = partition(vec![bad]).expect_err("a skipped item must still be validated");
            assert!(!err.is_retryable(), "a malformed annotation is terminal");
            let text = err.to_string();
            assert!(text.contains(expected), "{text}");
            assert!(text.contains("/Job/payments/ignored"), "{text}");
        }

        // A validly annotated `Skip` item is still partitioned out normally.
        let partition = partition(vec![resource_with(
            "Job",
            "ignored",
            &[
                (annotations::HOOK, "Skip"),
                (annotations::SYNC_WAVE, "-1"),
                (annotations::HOOK_DELETE_POLICY, "HookSucceeded"),
            ],
            None,
        )])
        .expect("a fully valid skipped item is not an error");
        assert!(partition.hooks().is_empty());
        assert_eq!(partition.skipped().len(), 1);
    }
}
