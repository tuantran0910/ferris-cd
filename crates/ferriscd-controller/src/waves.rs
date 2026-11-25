//! Sync-wave composition (`T10.2`) — the seam between the pure engine and the controller pass.
//!
//! The engine owns both halves of the model: [`ferriscd_engine::graph::hooks`] partitions a
//! rendered bundle into lifecycle hooks and permanent resources, and
//! [`ferriscd_engine::graph::waves`] groups the permanent half into ascending
//! `ferriscd.io/sync-wave` groups with the Phase 08 tier order inside each group. This module is
//! the small piece of glue those two need before a reconcile can act on them:
//!
//! ```text
//! manifest::load -> normalize -> scope -> BundleWaves::partition
//!                                              │
//!                     ┌────────────────────────┴─────────────────────────┐
//!                     ▼                                                  ▼
//!            hooks: HookPartition                          plan: WavePlan (permanent only)
//!            schedule(): SyncSchedule                     step_health(step, ..): StepHealth
//!                     └────────────────┬─────────────────────────────────┘
//!                                      ▼
//!                    SyncMachine::step  (pure, `T10.1`)
//!                                      ▼
//!                    StepAction::Execute -> apply the wave / run the hooks
//! ```
//!
//! # Which bundles engage the operation state machine
//!
//! [`BundleWaves::needs_operation`] is the switch. A bundle that is **one wave and has no hooks**
//! is applied in a single pass exactly like Phase 08: there is nothing to order and nothing to
//! wait for, so introducing a persisted phase would only add a requeue. Everything else — several
//! waves, any lifecycle hook, or an operation that is already running — is driven by
//! [`ferriscd_engine::sync::SyncMachine`] across requeues.
//!
//! # The wave gate
//!
//! [`step_health`] is where the state machine's contract is satisfied (finding M-1): the *expected*
//! set of a `Sync` step is the wave's permanent resources **plus** the hooks that share its wave
//! (finding M-2), and only resources the pass actually saw are *observed*. A resource that is
//! missing is therefore unobserved rather than "converging", which makes the machine re-dispatch
//! the step (an idempotent Server-Side Apply) instead of deadlocking on a wave whose write was lost
//! with a killed worker.

use std::collections::{BTreeMap, BTreeSet};

use ferriscd_crd::annotations;
use ferriscd_crd::status::{
    ActiveHook, ApplicationStatus, MAX_ACTIVE_HOOKS, OperationPhase, OperationState,
};
use ferriscd_engine::graph::hooks::{self, HookPartition, HookPhase};
use ferriscd_engine::graph::waves::WavePlan;
use ferriscd_engine::health::{self, HealthConfig, HealthInput, HealthRegistry, HealthStatus};
use ferriscd_engine::manifest::{DesiredResource, ManifestError, ResourceKey};
use ferriscd_engine::sync::{StepHealth, SyncPhase, SyncSchedule, SyncStep};

use crate::live_state::{LiveState, LiveStateMap};

/// The wave and hook structure of one rendered commit.
#[derive(Clone, Debug, Default)]
pub struct BundleWaves {
    /// Lifecycle hooks, partitioned out of the permanent set (`T10.3`).
    pub hooks: HookPartition,
    /// The permanent set grouped into ascending waves (`T10.2`).
    pub plan: WavePlan,
}

impl BundleWaves {
    /// Partitions a scope-normalized rendered bundle into hooks and ordered waves.
    ///
    /// # Errors
    ///
    /// Propagates the engine's terminal [`ManifestError::InvalidAnnotation`] for a malformed
    /// `ferriscd.io/hook`, `ferriscd.io/hook-delete-policy` or `ferriscd.io/sync-wave` value, and
    /// rejects a `ferriscd.io/hook: Sync` hook whose wave carries no permanent resource.
    pub fn partition(resources: Vec<DesiredResource>) -> Result<Self, ManifestError> {
        let hooks = hooks::partition(resources)?;
        // Built from the partition's permanent half: a hook must never reach the wave planner,
        // because a planned resource is applied as desired state and becomes prunable inventory.
        let plan = hooks.wave_plan()?;
        reject_wave_less_sync_hooks(&hooks, &plan)?;
        Ok(Self { hooks, plan })
    }

    /// Re-derives the wave plan from the (now stamped) permanent half.
    ///
    /// Ownership stamping mutates the permanent objects, and a `WavePlan` owns **clones** of them
    /// (it is a pure, self-contained value). A plan built before the stamp would therefore apply
    /// every wave member *without* `ferriscd.io/tracking-id`: the pruner would classify the live
    /// object as unmanaged (never prunable, never re-confirmed) and every wave's dry-run diff would
    /// report the missing annotation as drift forever. The controller must call this after
    /// stamping; [`crate::sync::InventorySyncPipeline`] does.
    ///
    /// # Errors
    ///
    /// Propagates [`ManifestError::InvalidAnnotation`] from the re-plan (already validated once, so
    /// this cannot fail for a bundle that partitioned successfully).
    pub fn replan(&mut self) -> Result<(), ManifestError> {
        self.plan = self.hooks.wave_plan()?;
        Ok(())
    }

    /// The steps of this commit's operation: `PreSync`, `Sync(wave)` ascending, `PostSync`.
    #[must_use]
    pub fn schedule(&self) -> SyncSchedule {
        SyncSchedule::from_plan(&self.plan)
    }

    /// Returns whether a reconcile of this bundle must be driven by the operation state machine.
    ///
    /// `running` is whether `status.operationState` is mid-operation: an in-flight sync is always
    /// resumed, whatever the commit now looks like, otherwise a mid-rollout pass would silently
    /// drop the persisted phase and restart from `PreSync` on the next drift.
    #[must_use]
    pub fn needs_operation(&self, running: bool) -> bool {
        running || self.hooks.has_hooks() || self.plan.wave_count() > 1
    }

    /// Returns whether the persisted operation is still running (`T10.1`).
    #[must_use]
    pub fn operation_running(status: Option<&ApplicationStatus>) -> bool {
        status
            .and_then(|status| status.operation_state.as_ref())
            .is_some_and(|state| state.phase == OperationPhase::Running)
    }
}

/// Builds the health set one state-machine step is judged on.
///
/// * `step.phase == Sync` — the wave's permanent resources **plus** every hook the pass observed
///   for that wave (a `ferriscd.io/hook: Sync` `Job` keeps its wave open, finding M-2).
/// * a hook phase — exactly the hooks the pass observed; no hook at all is
///   [`StepHealth::empty`], which the machine treats as trivially satisfied.
///
/// Only a `Present` live object is an observation: a `Missing`/deferred resource stays unobserved so
/// the machine re-dispatches the (idempotent) apply instead of waiting for a health read that will
/// never come (finding M-1).
#[must_use]
pub fn step_health(
    step: SyncStep,
    plan: &WavePlan,
    live: &LiveStateMap,
    hook_observations: &BTreeMap<ResourceKey, HealthStatus>,
    registry: &HealthRegistry,
    config: &HealthConfig,
) -> StepHealth {
    let wave_keys: Vec<ResourceKey> = if step.phase == SyncPhase::Sync {
        plan.keys_in(step.wave)
    } else {
        Vec::new()
    };

    let mut expected: Vec<ResourceKey> = wave_keys.clone();
    for key in hook_observations.keys() {
        if !expected.contains(key) {
            expected.push(key.clone());
        }
    }

    let inputs: Vec<HealthInput<'_>> = wave_keys
        .iter()
        .filter_map(|key| match live.get(key) {
            Some(LiveState::Present(object, _)) => Some(HealthInput::live(key, object.as_ref())),
            _ => None,
        })
        .collect();
    let summary = health::assess(&inputs, registry, config);

    // A `Sync` step of a wave the plan still contains always expects at least one resource (a
    // `WavePlan` never holds an empty wave), and `StepHealth::wave` debug-asserts it: a wave wired
    // with nothing to wait for would be "applied" and reported healthy without a single write
    // (finding M-1).
    //
    // The expected set can still be **empty** (finding H1): the commit changed between requeues and
    // the wave the persisted operation is on no longer exists (`keys_in` answers `[]` for a wave
    // that is not part of the plan). That is a normal, non-error situation — the state machine
    // restarts the operation for the new revision — so the step is judged as unobserved instead of
    // tripping the debug assertion.
    let mut health = if step.phase == SyncPhase::Sync && !expected.is_empty() {
        StepHealth::wave(expected)
    } else {
        StepHealth::unobserved(expected)
    };
    for assessment in summary.resources {
        health.observe(assessment.key, assessment.health.status);
    }
    for (key, status) in hook_observations {
        health.observe(key.clone(), *status);
    }
    health
}

/// A human-readable label of a `(phase, wave)` pair (`Sync(wave -1)`, `PreSync`).
#[must_use]
pub fn step_label(phase: SyncPhase, wave: i32) -> String {
    SyncStep::new(phase, wave).to_string()
}

/// Rejects a `ferriscd.io/hook: Sync` hook that lives in a wave holding no permanent resource
/// (finding M2).
///
/// A `Sync` hook runs *inside* a `Sync(wave)` step, and the schedule is built from the **wave plan**
/// ([`BundleWaves::schedule`] -> `SyncSchedule::from_plan`): a wave that only carries hooks never
/// produces a step, so the hook would silently never run. Silently is the problem — an inline
/// migration that never executes while the rollout reports `Succeeded` is worse than a failed sync —
/// so this is a terminal [`ManifestError::InvalidAnnotation`] naming the file, the resource and the
/// wave, and telling the author the two ways out.
fn reject_wave_less_sync_hooks(
    hooks: &HookPartition,
    plan: &WavePlan,
) -> Result<(), ManifestError> {
    for hook in hooks.hooks_in(HookPhase::Sync) {
        if plan.wave(hook.wave()).is_some() {
            continue;
        }
        return Err(ManifestError::InvalidAnnotation {
            file: hook.resource().source_file.clone(),
            message: format!(
                "{}: {}: Sync runs inside its wave's Sync step, but wave {} carries no permanent \
                 resource, so no step is scheduled for it and this hook would never run; move a \
                 permanent resource into wave {} or use PreSync/PostSync",
                hook.key().canonical(),
                annotations::HOOK,
                hook.wave(),
                hook.wave()
            ),
        });
    }
    Ok(())
}

/// The resources this pass has deliberately **not created yet** (finding M3).
///
/// Mid-rollout, everything in a wave the operation has not dispatched does not exist *by design*:
/// `PreSync` has applied nothing, `Sync(wave W)` has applied `w <= W`, and `PostSync` has applied
/// every wave. Those keys must be assessed as `Progressing` (scheduled) instead of `Missing`, or
/// `/status` reports a perfectly healthy rollout as broken between every pair of waves.
///
/// `operation` is the state this pass persists; a terminal (or absent) operation schedules nothing.
#[must_use]
pub fn scheduled_keys(
    plan: &WavePlan,
    operation: Option<&OperationState>,
) -> BTreeSet<ResourceKey> {
    let Some(operation) = operation.filter(|state| state.phase == OperationPhase::Running) else {
        return BTreeSet::new();
    };
    let phase = operation.sync_phase.unwrap_or(SyncPhase::Sync);
    let waves = plan.wave_numbers();
    let scheduled: Vec<i32> = match phase {
        // Nothing has been applied yet: every wave is still ahead of the pass.
        SyncPhase::PreSync => waves,
        SyncPhase::Sync => waves
            .into_iter()
            .filter(|wave| *wave > operation.current_wave)
            .collect(),
        // Every `Sync` wave has been dispatched; only the cleanup phases are left.
        SyncPhase::PostSync | SyncPhase::SyncFail | SyncPhase::Succeeded | SyncPhase::Failed => {
            Vec::new()
        }
    };
    scheduled
        .into_iter()
        .flat_map(|wave| plan.keys_in(wave))
        .collect()
}

/// Applies the hook records a pass produced to the persisted hook list.
///
/// Upsert by [`ActiveHook::hook_id`] — never append — so a requeue cannot duplicate a hook in
/// `/status` and the name recorded by the creating pass survives. The list is capped at
/// [`MAX_ACTIVE_HOOKS`] (finding M1): `/status` is an `etcd` object, so an unbounded tracking list
/// is a way to blow the 1.5 MiB limit. The oldest records are dropped (a hook is tracked from
/// creation in execution order, so the oldest entry is the least likely to still be running) and the
/// drop is logged, never silent.
pub fn merge_hook_records(tracked: &mut Vec<ActiveHook>, records: &[ActiveHook]) {
    for record in records {
        match tracked
            .iter_mut()
            .find(|existing| existing.hook_id == record.hook_id)
        {
            Some(existing) => *existing = record.clone(),
            None => tracked.push(record.clone()),
        }
    }
    let overflow = tracked.len().saturating_sub(MAX_ACTIVE_HOOKS);
    if overflow > 0 {
        tracked.drain(0..overflow);
        tracing::warn!(
            dropped = overflow,
            limit = MAX_ACTIVE_HOOKS,
            "status.operationState.activeHooks reached its bound: the oldest hook records were \
             dropped (a hook that is dropped is no longer observed, so a bundle with this many \
             hooks should use fewer lifecycle hooks)"
        );
    }
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::annotations;
    use ferriscd_crd::status::{OperationPhase, OperationState};
    use ferriscd_engine::manifest::GroupVersionKind;
    use ferriscd_engine::sync::SyncMachine;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use serde_json::json;

    use super::*;
    use ferriscd_engine::inventory::Ownership;

    fn resource(kind: &str, name: &str, wave: Option<&str>, hook: Option<&str>) -> DesiredResource {
        let (group, version) = match kind {
            "Job" => ("batch", "v1"),
            "Deployment" | "StatefulSet" => ("apps", "v1"),
            "CustomResourceDefinition" => ("apiextensions.k8s.io", "v1"),
            _ => ("", "v1"),
        };
        let api_version = if group.is_empty() {
            version.to_owned()
        } else {
            format!("{group}/{version}")
        };
        let mut control = serde_json::Map::new();
        if let Some(wave) = wave {
            control.insert(annotations::SYNC_WAVE.to_owned(), json!(wave));
        }
        if let Some(hook) = hook {
            control.insert(annotations::HOOK.to_owned(), json!(hook));
        }
        let mut metadata = json!({ "name": name, "namespace": "payments" });
        if !control.is_empty() {
            metadata["annotations"] = serde_json::Value::Object(control);
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
            source_file: format!("{kind}-{name}.yaml"),
        }
    }

    /// The live object of `resource` with a `status` block.
    fn live_present(resource: &DesiredResource, status: serde_json::Value) -> LiveState {
        let mut object = resource.object.clone();
        object.data["status"] = status;
        LiveState::Present(Box::new(object), Ownership::OwnedBySelf)
    }

    fn registry() -> HealthRegistry {
        HealthRegistry::builtin()
    }

    fn wave_health(
        bundle: &BundleWaves,
        step: SyncStep,
        live: &LiveStateMap,
        observations: &BTreeMap<ResourceKey, HealthStatus>,
    ) -> StepHealth {
        step_health(
            step,
            &bundle.plan,
            live,
            observations,
            &registry(),
            &HealthConfig::default(),
        )
    }

    #[test]
    fn a_bundle_without_hooks_or_waves_stays_single_pass() {
        let bundle = BundleWaves::partition(vec![
            resource("ConfigMap", "settings", None, None),
            resource("Deployment", "api", None, None),
        ])
        .expect("valid bundle");

        assert_eq!(bundle.plan.wave_count(), 1);
        assert!(!bundle.hooks.has_hooks());
        assert!(
            !bundle.needs_operation(false),
            "Phase 08 applies a single hook-less wave in one pass"
        );
        assert!(
            bundle.needs_operation(true),
            "an in-flight operation is always resumed"
        );
        assert_eq!(
            bundle.schedule().steps(),
            &[
                SyncStep::pre_sync(),
                SyncStep::sync(0),
                SyncStep::post_sync()
            ]
        );
    }

    #[test]
    fn several_waves_or_any_hook_engage_the_operation_state_machine() {
        let two_waves = BundleWaves::partition(vec![
            resource("Job", "migrate", Some("-1"), None),
            resource("Deployment", "api", None, None),
        ])
        .expect("valid bundle");
        assert!(two_waves.needs_operation(false));
        assert_eq!(two_waves.plan.wave_numbers(), vec![-1, 0]);

        let single_wave_with_hook = BundleWaves::partition(vec![
            resource("Job", "migrate", None, Some("PreSync")),
            resource("Deployment", "api", None, None),
        ])
        .expect("valid bundle");
        assert_eq!(single_wave_with_hook.plan.wave_count(), 1);
        assert!(
            single_wave_with_hook.needs_operation(false),
            "a hook has to be created and waited for, so it needs the state machine"
        );
        assert_eq!(
            single_wave_with_hook
                .hooks
                .permanent_inventory()
                .keys()
                .map(ResourceKey::canonical)
                .collect::<Vec<_>>(),
            vec!["apps/Deployment/payments/api".to_owned()],
            "the hook is never part of the permanent inventory"
        );
        assert_eq!(
            single_wave_with_hook.plan.keys().len(),
            1,
            "the hook is never applied as a wave member"
        );
    }

    #[test]
    fn operation_running_reads_the_persisted_phase() {
        let at = Time("2026-11-24T12:00:00Z".parse().expect("valid RFC 3339"));
        let mut status = ApplicationStatus::default();
        assert!(!BundleWaves::operation_running(None));
        assert!(!BundleWaves::operation_running(Some(&status)));

        status.operation_state = Some(OperationState {
            phase: OperationPhase::Running,
            sync_phase: Some(SyncPhase::Sync),
            current_wave: -1,
            phase_started_at: Some(at.clone()),
            revision: Some("abc".to_owned()),
            active_hooks: Vec::new(),
            message: None,
            started_at: at.clone(),
            finished_at: None,
        });
        assert!(BundleWaves::operation_running(Some(&status)));

        if let Some(state) = status.operation_state.as_mut() {
            state.phase = OperationPhase::Succeeded;
            state.finished_at = Some(at);
        }
        assert!(!BundleWaves::operation_running(Some(&status)));
    }

    /// Finding M-1: a wave with nothing observed is *unobserved*, so the machine re-dispatches the
    /// apply instead of deadlocking on a health read that will never come.
    #[test]
    fn an_unobserved_wave_is_unobserved_not_converging() {
        let migration = resource("Job", "migrate", Some("-1"), None);
        let bundle = BundleWaves::partition(vec![migration.clone()]).expect("valid bundle");

        let health = wave_health(
            &bundle,
            SyncStep::sync(-1),
            &LiveStateMap::new(),
            &BTreeMap::new(),
        );
        assert!(health.is_unobserved(), "{health:?}");
        assert_eq!(health.expected(), std::slice::from_ref(&migration.key));
    }

    /// Finding M-2: a `Sync` hook keeps its wave open, and a wave is only satisfied when *every*
    /// resource and hook is `Healthy`.
    #[test]
    fn a_wave_is_satisfied_only_when_every_resource_and_hook_is_healthy() {
        let settings = resource("ConfigMap", "settings", None, None);
        let secret = resource("Secret", "credentials", None, None);
        let bundle =
            BundleWaves::partition(vec![settings.clone(), secret.clone()]).expect("valid bundle");

        let mut live = LiveStateMap::new();
        live.insert(settings.key.clone(), live_present(&settings, json!({})));
        live.insert(secret.key.clone(), live_present(&secret, json!({})));

        let healthy = wave_health(&bundle, SyncStep::sync(0), &live, &BTreeMap::new());
        assert_eq!(healthy.expected().len(), 2);
        assert_eq!(healthy.observed().len(), 2);
        assert_eq!(healthy.aggregate(), HealthStatus::Healthy);

        // A hook that is still running keeps the wave open even though every permanent resource is
        // healthy (a wave whose inline migration is still running must not advance).
        let hook_key = ResourceKey::new("batch", "Job", Some("payments".to_owned()), "inline");
        let observations = BTreeMap::from([(hook_key.clone(), HealthStatus::Progressing)]);
        let with_hook = wave_health(&bundle, SyncStep::sync(0), &live, &observations);
        assert_eq!(with_hook.expected().len(), 3);
        assert!(
            with_hook.expected().contains(&hook_key),
            "a Sync hook is part of its wave's expected set"
        );
        assert_eq!(
            with_hook.observed().get(&hook_key),
            Some(&HealthStatus::Progressing)
        );

        // A `Degraded` hook is observed as `Degraded`, which the machine turns into `SyncFail`.
        let degraded = BTreeMap::from([(hook_key.clone(), HealthStatus::Degraded)]);
        let failing = wave_health(&bundle, SyncStep::sync(0), &live, &degraded);
        assert_eq!(failing.degraded(), vec![hook_key]);
    }

    /// A resource that only exists in *another* wave is never part of this wave's expected set: a
    /// wave gates on what it applied, not on the whole commit.
    #[test]
    fn a_wave_only_expects_its_own_resources() {
        let migration = resource("Job", "migrate", Some("-1"), None);
        let api = resource("Deployment", "api", None, None);
        let bundle = BundleWaves::partition(vec![migration.clone(), api.clone()]).expect("valid");

        let early = wave_health(
            &bundle,
            SyncStep::sync(-1),
            &LiveStateMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(early.expected(), std::slice::from_ref(&migration.key));
        let late = wave_health(
            &bundle,
            SyncStep::sync(0),
            &LiveStateMap::new(),
            &BTreeMap::new(),
        );
        assert_eq!(late.expected(), std::slice::from_ref(&api.key));
    }

    #[test]
    fn a_hook_phase_is_judged_on_its_hooks_only() {
        let migration = resource("Job", "migrate", None, Some("PreSync"));
        let api = resource("Deployment", "api", None, None);
        let bundle = BundleWaves::partition(vec![migration.clone(), api]).expect("valid bundle");

        // No hook observed yet (no hook in the commit either): trivially satisfied.
        let empty = wave_health(
            &bundle,
            SyncStep::post_sync(),
            &LiveStateMap::new(),
            &BTreeMap::new(),
        );
        assert!(empty.expected().is_empty());
        assert!(
            !empty.is_unobserved(),
            "an empty step is trivially satisfied"
        );

        // A created hook that is still running keeps the phase open.
        let running = BTreeMap::from([(migration.key.clone(), HealthStatus::Progressing)]);
        let health = wave_health(
            &bundle,
            SyncStep::pre_sync(),
            &LiveStateMap::new(),
            &running,
        );
        assert_eq!(health.expected(), std::slice::from_ref(&migration.key));
        assert_eq!(
            health.observed().get(&migration.key),
            Some(&HealthStatus::Progressing)
        );
    }

    /// The trap guard wiring: the wave that carries a CRD is exactly the one that forces a discovery
    /// refresh before the next wave.
    #[test]
    fn the_wave_plan_reports_which_wave_needs_a_discovery_refresh() {
        let bundle = BundleWaves::partition(vec![
            resource("CustomResourceDefinition", "widgets", Some("-1"), None),
            resource("Job", "migrate", Some("-1"), None),
            resource("Deployment", "api", None, None),
        ])
        .expect("valid bundle");

        assert!(bundle.plan.contains_crd(-1));
        assert!(!bundle.plan.contains_crd(0));
        assert_eq!(bundle.plan.crd_waves(), vec![-1]);
    }

    /// The wave plan owns clones, so stamping the permanent half must be followed by `replan()`:
    /// otherwise every wave would be applied without its ownership marker.
    #[test]
    fn replan_propagates_the_ownership_stamp_into_the_wave_plan() {
        let settings = resource("ConfigMap", "settings", Some("-1"), None);
        let mut bundle = BundleWaves::partition(vec![settings.clone()]).expect("valid bundle");
        let tracking_id = |bundle: &BundleWaves| {
            bundle.plan.wave(-1).expect("wave -1").resources[0]
                .object
                .metadata
                .annotations
                .as_ref()
                .and_then(|map| map.get(ferriscd_crd::annotations::TRACKING_ID).cloned())
        };
        assert_eq!(tracking_id(&bundle), None, "the fixture starts unstamped");

        ferriscd_engine::inventory::stamp_tracking_id(
            &mut bundle.hooks.permanent_mut()[0],
            "ferriscd-system",
            "payments",
        )
        .expect("stamping a plain object never fails");
        bundle.replan().expect("the plan is re-derivable");

        assert_eq!(
            tracking_id(&bundle).as_deref(),
            Some("ferriscd-system/payments:/ConfigMap:payments/settings"),
            "a wave member must carry the ownership marker it is applied with"
        );
    }

    #[test]
    fn hook_records_are_upserted_never_appended() {
        let mut tracked = vec![ActiveHook::new(
            SyncPhase::PreSync,
            0,
            "a.yaml#0",
            "migrate-1",
            HealthStatus::Progressing,
        )];
        merge_hook_records(
            &mut tracked,
            &[ActiveHook::new(
                SyncPhase::PreSync,
                0,
                "a.yaml#0",
                "migrate-1",
                HealthStatus::Healthy,
            )],
        );
        assert_eq!(tracked.len(), 1, "a requeue must never duplicate a record");
        assert_eq!(tracked[0].health, HealthStatus::Healthy);

        merge_hook_records(
            &mut tracked,
            &[ActiveHook::new(
                SyncPhase::PostSync,
                0,
                "b.yaml#0",
                "smoke",
                HealthStatus::Progressing,
            )],
        );
        assert_eq!(tracked.len(), 2);
    }

    #[test]
    fn malformed_control_annotations_are_terminal() {
        let bad = resource("Job", "migrate", Some("soon"), None);
        let err = BundleWaves::partition(vec![bad]).expect_err("invalid wave must be rejected");
        assert!(!err.is_retryable());
        assert!(err.to_string().contains(annotations::SYNC_WAVE), "{err}");
    }

    /// A persisted `OperationState` fixture (`timeouts`/`now` do not matter for these tests).
    fn operation(phase: SyncPhase, wave: i32, revision: &str) -> OperationState {
        let at = Time("2026-11-24T12:00:00Z".parse().expect("valid RFC 3339"));
        OperationState {
            phase: OperationPhase::Running,
            sync_phase: Some(phase),
            current_wave: wave,
            phase_started_at: Some(at.clone()),
            revision: Some(revision.to_owned()),
            active_hooks: Vec::new(),
            message: None,
            started_at: at,
            finished_at: None,
        }
    }

    /// **Finding H1:** a `Sync` step whose wave vanished from the plan (the commit changed between
    /// requeues) must not reach `StepHealth::wave`, which debug-asserts a non-empty expectation.
    /// The step is judged on an empty expected set, and the machine restarts the operation for the
    /// new revision.
    #[test]
    fn a_vanished_wave_is_judged_unobserved_and_restarts_the_operation() {
        let api = resource("Deployment", "api", None, None);
        let bundle = BundleWaves::partition(vec![api.clone()]).expect("valid bundle");
        assert!(
            bundle.plan.wave(-1).is_none(),
            "the fixture really no longer carries wave -1"
        );

        // The persisted operation is on `Sync(wave -1)`, which this commit does not have. This is
        // the call that used to trip `StepHealth::wave`'s debug assertion.
        let health = wave_health(
            &bundle,
            SyncStep::sync(-1),
            &LiveStateMap::new(),
            &BTreeMap::new(),
        );
        assert!(health.expected().is_empty());
        assert!(
            !health.is_unobserved(),
            "an empty step is trivially satisfied"
        );

        let machine = SyncMachine::default();
        let persisted = operation(SyncPhase::Sync, -1, "oldsha");
        let outcome = machine.step(
            &persisted,
            &bundle.schedule(),
            &health,
            Some("newsha"),
            &Time("2026-11-24T12:00:00Z".parse().expect("valid RFC 3339")),
        );
        assert_eq!(
            outcome.state.sync_phase,
            Some(SyncPhase::PreSync),
            "a vanished wave is not a failure: the new revision restarts the operation"
        );
        assert_eq!(outcome.state.current_wave, 0);
        assert_eq!(outcome.state.revision.as_deref(), Some("newsha"));
        assert_eq!(
            outcome.action.step(),
            Some(SyncStep::pre_sync()),
            "the restart dispatches PreSync for the new commit"
        );
    }

    /// **Finding M2:** a `Sync` hook only runs inside its wave's `Sync(wave)` step, and the schedule
    /// is planned from the *permanent* waves. A `Sync` hook in a wave with no permanent resource
    /// would therefore never run — silently. It is rejected as a terminal manifest error instead.
    #[test]
    fn a_sync_hook_in_a_wave_without_a_permanent_resource_is_rejected() {
        let err = BundleWaves::partition(vec![
            resource("Job", "inline", Some("2"), Some("Sync")),
            resource("Deployment", "api", None, None),
        ])
        .expect_err("wave 2 is not planned, so the Sync hook has no step to run in");
        assert!(
            matches!(err, ManifestError::InvalidAnnotation { .. }),
            "unexpected error: {err:?}"
        );
        assert!(!err.is_retryable(), "the annotation is part of the commit");
        let text = err.to_string();
        assert!(text.contains(annotations::HOOK), "{text}");
        assert!(text.contains("wave 2"), "{text}");
        assert!(text.contains("/Job/payments/inline"), "{text}");
        assert!(text.contains("Job-inline.yaml"), "{text}");
        assert!(
            text.contains("PreSync"),
            "the message must name the way out: {text}"
        );

        // The same hook is fine as soon as its wave carries a permanent resource.
        let bundle = BundleWaves::partition(vec![
            resource("Job", "inline", Some("2"), Some("Sync")),
            resource("ConfigMap", "settings", Some("2"), None),
        ])
        .expect("wave 2 is planned, so its Sync hook has a step to run in");
        assert_eq!(bundle.plan.wave_numbers(), vec![2]);
        assert_eq!(
            bundle
                .hooks
                .hooks_in(HookPhase::Sync)
                .iter()
                .map(|hook| hook.key().name.clone())
                .collect::<Vec<_>>(),
            vec!["inline".to_owned()]
        );

        // A bundle of hooks alone plans no wave at all, so a `Sync` hook there is rejected too.
        let only_hooks = BundleWaves::partition(vec![
            resource("Job", "inline", None, Some("Sync")),
            resource("Job", "notify", None, Some("PostSync")),
        ]);
        assert!(
            only_hooks.is_err(),
            "a Sync hook next to a PostSync hook has no wave to run in"
        );
    }

    /// **Finding M3:** the resources of a wave the running operation has not dispatched yet are
    /// *scheduled*, so the pass reports them `Progressing` instead of `Missing`.
    #[test]
    fn resources_of_a_wave_the_operation_has_not_reached_are_scheduled() {
        let migration = resource("Job", "migrate", Some("-1"), None);
        let api = resource("Deployment", "api", None, None);
        let bundle =
            BundleWaves::partition(vec![migration.clone(), api.clone()]).expect("valid bundle");
        let both = BTreeSet::from([migration.key.clone(), api.key.clone()]);

        // No operation at all: a plain drift pass assesses exactly what Git asks for.
        assert!(scheduled_keys(&bundle.plan, None).is_empty());

        // `PreSync` has applied nothing yet, so every wave is still ahead of this pass.
        assert_eq!(
            scheduled_keys(&bundle.plan, Some(&operation(SyncPhase::PreSync, 0, "sha"))),
            both
        );
        // `Sync(wave -1)` applied wave -1, so only wave 0 is scheduled.
        assert_eq!(
            scheduled_keys(&bundle.plan, Some(&operation(SyncPhase::Sync, -1, "sha"))),
            BTreeSet::from([api.key.clone()])
        );
        // The last wave has been dispatched, and `PostSync` runs after every wave.
        assert!(
            scheduled_keys(&bundle.plan, Some(&operation(SyncPhase::Sync, 0, "sha"))).is_empty()
        );
        assert!(
            scheduled_keys(
                &bundle.plan,
                Some(&operation(SyncPhase::PostSync, 0, "sha"))
            )
            .is_empty()
        );

        // A terminal operation schedules nothing: a `Failed` rollout's resources are really absent.
        let mut failed = operation(SyncPhase::Failed, 0, "sha");
        failed.phase = OperationPhase::Failed;
        assert!(scheduled_keys(&bundle.plan, Some(&failed)).is_empty());
        let mut succeeded = operation(SyncPhase::Succeeded, 0, "sha");
        succeeded.phase = OperationPhase::Succeeded;
        assert!(scheduled_keys(&bundle.plan, Some(&succeeded)).is_empty());
    }

    /// **Finding M1:** `/status` is an `etcd` object, so the tracked-hook list is bounded by
    /// [`MAX_ACTIVE_HOOKS`] — a pathological bundle must never be able to grow it without limit.
    #[test]
    fn hook_records_are_bounded_by_max_active_hooks() {
        let records: Vec<ActiveHook> = (0..MAX_ACTIVE_HOOKS + 5)
            .map(|index| {
                ActiveHook::new(
                    SyncPhase::PreSync,
                    0,
                    format!("hooks.yaml#{index}"),
                    format!("migrate-{index}"),
                    HealthStatus::Progressing,
                )
            })
            .collect();

        let mut tracked = Vec::new();
        merge_hook_records(&mut tracked, &records);
        assert_eq!(
            tracked.len(),
            MAX_ACTIVE_HOOKS,
            "the tracking list is bounded"
        );
        assert!(
            !tracked.iter().any(|hook| hook.hook_id == "hooks.yaml#0"),
            "the oldest records are the ones that were dropped"
        );
        assert!(
            tracked
                .iter()
                .any(|hook| hook.hook_id == format!("hooks.yaml#{}", MAX_ACTIVE_HOOKS + 4)),
            "the newest record is always kept"
        );

        // Re-merging records that are already tracked never grows the list (nor drops anything).
        let before = tracked.clone();
        merge_hook_records(&mut tracked, &records[MAX_ACTIVE_HOOKS..]);
        assert_eq!(tracked.len(), MAX_ACTIVE_HOOKS);
        assert_eq!(tracked, before);
    }
}
