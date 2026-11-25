//! Core workload health (`T09.2`): `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`.
//!
//! These four kinds are the hardest health state machines in Kubernetes because their `status`
//! counters are *rollout* bookkeeping, not a verdict. Four traps are handled here:
//!
//! | Trap | Naive code | Consequence | Fix |
//! |---|---|---|---|
//! | stale `observedGeneration` | `updatedReplicas == availableReplicas == desired ⇒ Healthy` | the *previous* rollout's counters are still there for a pass or two after an edit, so a just-edited `spec` reports `Healthy` before a single new pod exists | every evaluator checks `status.observedGeneration` first ([`generation_gate`]) |
//! | `spec.paused` | same counters | a paused `Deployment` never updates its status, so it is `Progressing` forever and a sync wave never advances | check `paused` **before** the generation gate → `Suspended` |
//! | `replicas: 0` | `available == desired` with `available == 0` reading as "not ready" in hand-rolled code | a deliberately scaled-down workload reports `Progressing` forever | explicit `desired == 0 && status.replicas == 0 ⇒ Healthy` |
//! | `OnDelete` StatefulSet / `partition` | `updatedReplicas == replicas` | `updatedReplicas` only advances when a human deletes a pod, so a healthy `OnDelete` cluster reports `Progressing` forever | `OnDelete` waits on readiness only; a partition requires `updatedReplicas >= replicas - partition` |
//!
//! Every message is derived from `status`/`spec` counters only, never from `data`, so nothing here
//! can echo a secret.

use kube::api::DynamicObject;

use super::values;
use super::{HealthConfig, HealthEvaluator, MSG_WAITING_FOR_OBSERVATION, ResourceHealth};

/// The `Deployment` controller's fatal rollout condition reason.
pub const PROGRESS_DEADLINE_EXCEEDED: &str = "ProgressDeadlineExceeded";

/// `StatefulSet` update strategy that requires a human to delete pods.
pub const ON_DELETE: &str = "OnDelete";

/// Returns `Progressing` while `status.observedGeneration` lags `metadata.generation`.
///
/// Returns `None` when the generation is unknown (an object the API server has not stamped, e.g. a
/// fixture or a dry-run payload) or when the controller has already observed it.
#[must_use]
pub fn generation_gate(object: &DynamicObject) -> Option<ResourceHealth> {
    let generation = object.metadata.generation?;
    match values::int(object, &["status", "observedGeneration"]) {
        Some(observed) if observed >= generation => None,
        _ => Some(ResourceHealth::progressing(MSG_WAITING_FOR_OBSERVATION)),
    }
}

/// Returns `true` when the `Deployment`/`StatefulSet` is scaled to zero and has nothing left.
fn scaled_to_zero(object: &DynamicObject, desired: u32) -> Option<ResourceHealth> {
    if desired > 0 {
        return None;
    }
    let current = values::count(object, &["status", "replicas"]);
    Some(if current == 0 {
        ResourceHealth::healthy("scaled to zero replicas")
    } else {
        ResourceHealth::progressing(format!(
            "waiting for {current} pod(s) to terminate after a scale-down"
        ))
    })
}

/// `Deployment` health (`T09.2`).
#[derive(Debug, Clone, Copy)]
pub struct DeploymentHealth;

impl HealthEvaluator for DeploymentHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        deployment(object)
    }
}

/// `Deployment` health, exposed as a pure function for the snapshot tests.
///
/// Order of the checks is the contract:
/// 1. `spec.paused` → `Suspended`. **Before** the generation gate: a paused controller stops
///    writing `status`, so a `spec` edit made while paused never advances
///    `observedGeneration` and the generation gate would report `Progressing` forever.
/// 2. `observedGeneration` lag → `Progressing`.
/// 3. `spec.replicas == 0` → `Healthy` once `status.replicas == 0` (**before** the deadline
///    check: a deliberately scaled-down Deployment can still carry a stale
///    `ProgressDeadlineExceeded` condition from the rollout it was scaled down from).
/// 4. `Progressing=False` with `ProgressDeadlineExceeded` → `Degraded`.
/// 5. `updatedReplicas == availableReplicas == desired` → `Healthy`, otherwise `Progressing`.
#[must_use]
pub fn deployment(object: &DynamicObject) -> ResourceHealth {
    if values::flag(object, &["spec", "paused"]).unwrap_or(false) {
        return ResourceHealth::suspended("Deployment is paused (spec.paused=true)");
    }
    if let Some(gate) = generation_gate(object) {
        return gate;
    }

    let desired = values::count_opt(object, &["spec", "replicas"]).unwrap_or(1);
    if let Some(zero) = scaled_to_zero(object, desired) {
        return zero;
    }
    if let Some(dead) = progress_deadline(object) {
        return dead;
    }

    let updated = values::count(object, &["status", "updatedReplicas"]);
    let available = values::count(object, &["status", "availableReplicas"]);
    let ready = values::count(object, &["status", "readyReplicas"]);

    if updated == desired && available == desired {
        ResourceHealth::healthy(format!(
            "all {desired} replica(s) are updated and available"
        ))
    } else {
        ResourceHealth::progressing(format!(
            "waiting for the rollout: {updated}/{desired} updated, {available}/{desired} available, \
             {ready}/{desired} ready"
        ))
    }
}

/// Maps the `Deployment`'s `Progressing` condition onto a verdict when it reports failure.
fn progress_deadline(object: &DynamicObject) -> Option<ResourceHealth> {
    let conditions = values::conditions(object);
    let condition = values::condition(&conditions, "Progressing")?;
    if !condition.is_false() {
        return None;
    }
    if condition.reason == PROGRESS_DEADLINE_EXCEEDED {
        return Some(ResourceHealth::degraded(format!(
            "Deployment exceeded its progress deadline ({})",
            condition.describe()
        )));
    }
    // Any other `Progressing=False` is not documented as terminal, so report it as still
    // converging instead of inventing a failure.
    Some(ResourceHealth::progressing(format!(
        "Deployment reports Progressing=False ({})",
        condition.describe()
    )))
}

/// `StatefulSet` health (`T09.2`).
#[derive(Debug, Clone, Copy)]
pub struct StatefulSetHealth;

impl HealthEvaluator for StatefulSetHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        stateful_set(object)
    }
}

/// `StatefulSet` health, exposed as a pure function.
///
/// The two strategies must not be conflated:
///
/// * `RollingUpdate` (default): every replica must be updated. With a `partition`, the controller
///   is *supposed* to leave the first `partition` ordinals alone, so only
///   `replicas - partition` updates are required — waiting for `updatedReplicas == replicas`
///   hangs a partitioned (canary) StatefulSet forever.
/// * `OnDelete`: the controller never updates a pod on its own, so `updatedReplicas` does not
///   advance when the `spec` changes. Health is readiness only.
#[must_use]
pub fn stateful_set(object: &DynamicObject) -> ResourceHealth {
    if let Some(gate) = generation_gate(object) {
        return gate;
    }

    let desired = values::count_opt(object, &["spec", "replicas"]).unwrap_or(1);
    if let Some(zero) = scaled_to_zero(object, desired) {
        return zero;
    }

    let current = values::count(object, &["status", "replicas"]);
    let ready = values::count(object, &["status", "readyReplicas"]);
    let updated = values::count(object, &["status", "updatedReplicas"]);
    let strategy = values::text(object, &["spec", "updateStrategy", "type"]).unwrap_or_default();

    if strategy == ON_DELETE {
        // `updatedReplicas` only moves when an operator deletes a pod, so it is not a health
        // signal here; `status.currentRevision == updateRevision` is the real "everything has
        // been rolled" marker, but readiness alone is what an OnDelete owner cares about.
        return if ready >= desired && current >= desired {
            ResourceHealth::healthy(format!(
                "all {desired} replica(s) are ready (OnDelete: pods are replaced manually)"
            ))
        } else {
            ResourceHealth::progressing(format!(
                "{ready}/{desired} replica(s) ready, {current} created (OnDelete updates are manual)"
            ))
        };
    }

    let partition = values::count(
        object,
        &["spec", "updateStrategy", "rollingUpdate", "partition"],
    );
    let required_updated = desired.saturating_sub(partition);

    if updated >= required_updated && ready >= desired && current >= desired {
        let partition_note = if partition > 0 {
            format!(
                "; {partition} ordinal(s) pinned by spec.updateStrategy.rollingUpdate.partition"
            )
        } else {
            String::new()
        };
        return ResourceHealth::healthy(format!(
            "{ready}/{desired} replica(s) ready, {updated} updated{partition_note}"
        ));
    }

    ResourceHealth::progressing(format!(
        "waiting for the rollout: {updated}/{required_updated} required update(s), {ready}/{desired} \
         ready, {current} created"
    ))
}

/// `DaemonSet` health (`T09.2`).
#[derive(Debug, Clone, Copy)]
pub struct DaemonSetHealth;

impl HealthEvaluator for DaemonSetHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        daemon_set(object)
    }
}

/// `DaemonSet` health, exposed as a pure function.
///
/// A `DaemonSet` whose selector matches no node reports `desiredNumberScheduled: 0`. That is not a
/// failure — on a single-node `kind` cluster a `node-role.kubernetes.io/control-plane` toleration
/// mistake produces exactly this — so it is `Healthy` rather than a rollout that never finishes.
#[must_use]
pub fn daemon_set(object: &DynamicObject) -> ResourceHealth {
    if let Some(gate) = generation_gate(object) {
        return gate;
    }

    let desired = values::count(object, &["status", "desiredNumberScheduled"]);
    if desired == 0 {
        return ResourceHealth::healthy(
            "DaemonSet schedules no pods (no node matches its selector)",
        );
    }

    let updated = values::count(object, &["status", "updatedNumberScheduled"]);
    let available = values::count(object, &["status", "numberAvailable"]);
    let ready = values::count(object, &["status", "numberReady"]);

    if updated == desired && available == desired {
        ResourceHealth::healthy(format!(
            "all {desired} node(s) run an updated, available pod"
        ))
    } else {
        ResourceHealth::progressing(format!(
            "waiting for the rollout: {updated}/{desired} updated, {available}/{desired} available, \
             {ready}/{desired} ready"
        ))
    }
}

/// `ReplicaSet` health (`T09.2`).
///
/// A `ReplicaSet` is usually owned by a `Deployment`, but it can also be managed directly from Git
/// (and it is listed in `status.inventory` even when it is a `Deployment`'s child, because the
/// bundle declares it). Health is `availableReplicas == spec.replicas`.
#[derive(Debug, Clone, Copy)]
pub struct ReplicaSetHealth;

impl HealthEvaluator for ReplicaSetHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        replica_set(object)
    }
}

/// `ReplicaSet` health, exposed as a pure function.
#[must_use]
pub fn replica_set(object: &DynamicObject) -> ResourceHealth {
    if let Some(gate) = generation_gate(object) {
        return gate;
    }

    let desired = values::count_opt(object, &["spec", "replicas"]).unwrap_or(1);
    if let Some(zero) = scaled_to_zero(object, desired) {
        return zero;
    }

    let current = values::count(object, &["status", "replicas"]);
    let available = values::count(object, &["status", "availableReplicas"]);
    let ready = values::count(object, &["status", "readyReplicas"]);

    if available >= desired && current >= desired {
        ResourceHealth::healthy(format!("{available}/{desired} replica(s) are available"))
    } else {
        ResourceHealth::progressing(format!(
            "{available}/{desired} replica(s) available, {ready} ready, {current} created"
        ))
    }
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::status::HealthStatus;
    use kube::api::DynamicObject;
    use serde_json::json;

    use super::*;

    fn object(value: serde_json::Value) -> DynamicObject {
        serde_json::from_value(value).expect("valid DynamicObject")
    }

    /// A `Deployment` fixture: `metadata.generation` 2 and an observed generation of 2 unless the
    /// test overrides them, which is what a settled rollout looks like.
    fn deployment_fixture(spec: serde_json::Value, status: serde_json::Value) -> DynamicObject {
        object(json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "api", "namespace": "payments", "generation": 2 },
            "spec": spec,
            "status": status,
        }))
    }

    // ---------------------------------------------------------------------
    // Deployment
    // ---------------------------------------------------------------------

    #[test]
    fn a_settled_deployment_is_healthy() {
        let live = deployment_fixture(
            json!({ "replicas": 3 }),
            json!({
                "observedGeneration": 2,
                "replicas": 3,
                "updatedReplicas": 3,
                "availableReplicas": 3,
                "readyReplicas": 3,
            }),
        );
        let health = deployment(&live);
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(
            health.message.contains("all 3 replica(s)"),
            "{}",
            health.message
        );
    }

    /// Trap: the *previous* rollout's counters are still in `status` after an edit.
    #[test]
    fn a_stale_observed_generation_is_never_healthy() {
        let live = deployment_fixture(
            json!({ "replicas": 3 }),
            json!({
                "observedGeneration": 1,
                "replicas": 3,
                "updatedReplicas": 3,
                "availableReplicas": 3,
                "readyReplicas": 3,
            }),
        );
        let health = deployment(&live);
        assert_eq!(
            health.status,
            HealthStatus::Progressing,
            "an unobserved spec edit must never look healthy"
        );
        assert_eq!(health.message, MSG_WAITING_FOR_OBSERVATION);

        // No `status` at all (the object was just created) behaves the same way.
        let fresh = deployment_fixture(json!({ "replicas": 1 }), json!({}));
        assert_eq!(deployment(&fresh).message, MSG_WAITING_FOR_OBSERVATION);
    }

    #[test]
    fn a_paused_deployment_is_suspended_even_when_its_status_is_stale() {
        // Paused + a spec edit the controller will never observe: the pause must win, otherwise
        // the Application would report Progressing forever.
        let live = deployment_fixture(
            json!({ "paused": true, "replicas": 5 }),
            json!({ "observedGeneration": 1, "replicas": 2 }),
        );
        assert_eq!(deployment(&live).status, HealthStatus::Suspended);

        // Paused but otherwise fully rolled out: still Suspended, not Healthy.
        let rolled = deployment_fixture(
            json!({ "paused": true, "replicas": 2 }),
            json!({
                "observedGeneration": 2,
                "replicas": 2,
                "updatedReplicas": 2,
                "availableReplicas": 2,
            }),
        );
        assert_eq!(deployment(&rolled).status, HealthStatus::Suspended);
    }

    #[test]
    fn a_deployment_past_its_progress_deadline_is_degraded() {
        let live = deployment_fixture(
            json!({ "replicas": 2 }),
            json!({
                "observedGeneration": 2,
                "replicas": 2,
                "updatedReplicas": 2,
                "availableReplicas": 1,
                "readyReplicas": 0,
                "conditions": [{
                    "type": "Progressing",
                    "status": "False",
                    "reason": "ProgressDeadlineExceeded",
                    "message": "ReplicaSet \"api-6f9\" has timed out progressing.",
                }],
            }),
        );
        let health = deployment(&live);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("progress deadline") && health.message.contains("timed out"),
            "{}",
            health.message
        );

        // `Progressing=True` (a healthy rollout in progress) is not a failure.
        let rolling = deployment_fixture(
            json!({ "replicas": 2 }),
            json!({
                "observedGeneration": 2,
                "replicas": 2,
                "updatedReplicas": 1,
                "availableReplicas": 1,
                "conditions": [{
                    "type": "Progressing",
                    "status": "True",
                    "reason": "ReplicaSetUpdated",
                }],
            }),
        );
        assert_eq!(deployment(&rolling).status, HealthStatus::Progressing);

        // An undocumented `Progressing=False` reason stays Progressing: we cannot know it is fatal.
        let unexplained = deployment_fixture(
            json!({ "replicas": 2 }),
            json!({
                "observedGeneration": 2,
                "replicas": 2,
                "updatedReplicas": 2,
                "availableReplicas": 1,
                "conditions": [{
                    "type": "Progressing",
                    "status": "False",
                    "reason": "SomethingNew",
                }],
            }),
        );
        assert_eq!(deployment(&unexplained).status, HealthStatus::Progressing);
    }

    #[test]
    fn a_deployment_scaled_to_zero_is_healthy_once_it_has_no_pods() {
        let settled = deployment_fixture(
            json!({ "replicas": 0 }),
            json!({ "observedGeneration": 2, "replicas": 0 }),
        );
        assert_eq!(deployment(&settled).status, HealthStatus::Healthy);

        let draining = deployment_fixture(
            json!({ "replicas": 0 }),
            json!({ "observedGeneration": 2, "replicas": 1, "availableReplicas": 1 }),
        );
        assert_eq!(deployment(&draining).status, HealthStatus::Progressing);
        assert!(
            draining_message(&draining).contains("terminate"),
            "{}",
            draining_message(&draining)
        );

        // Scaling down is the normal response to a failed rollout: the stale
        // ProgressDeadlineExceeded condition must not outrank `replicas: 0`.
        let scaled_down_after_failure = deployment_fixture(
            json!({ "replicas": 0 }),
            json!({
                "observedGeneration": 2,
                "replicas": 0,
                "conditions": [{
                    "type": "Progressing",
                    "status": "False",
                    "reason": "ProgressDeadlineExceeded",
                }],
            }),
        );
        assert_eq!(
            deployment(&scaled_down_after_failure).status,
            HealthStatus::Healthy,
            "a deliberately scaled-down Deployment must not stay Degraded"
        );

        // An absent `spec.replicas` means the Kubernetes default of 1.
        let defaulted = deployment_fixture(
            json!({}),
            json!({
                "observedGeneration": 2,
                "replicas": 1,
                "updatedReplicas": 1,
                "availableReplicas": 1,
            }),
        );
        assert_eq!(deployment(&defaulted).status, HealthStatus::Healthy);
    }

    fn draining_message(object: &DynamicObject) -> String {
        deployment(object).message
    }

    #[test]
    fn a_partially_rolled_deployment_is_progressing() {
        let live = deployment_fixture(
            json!({ "replicas": 3 }),
            json!({
                "observedGeneration": 2,
                "replicas": 3,
                "updatedReplicas": 2,
                "availableReplicas": 2,
                "readyReplicas": 2,
            }),
        );
        let health = deployment(&live);
        assert_eq!(health.status, HealthStatus::Progressing);
        assert!(
            health.message.contains("2/3 updated") && health.message.contains("2/3 available"),
            "{}",
            health.message
        );
    }

    // ---------------------------------------------------------------------
    // StatefulSet
    // ---------------------------------------------------------------------

    fn stateful_set_fixture(spec: serde_json::Value, status: serde_json::Value) -> DynamicObject {
        object(json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": { "name": "db", "namespace": "payments", "generation": 3 },
            "spec": spec,
            "status": status,
        }))
    }

    #[test]
    fn a_settled_stateful_set_is_healthy_and_a_stale_one_is_not() {
        let settled = stateful_set_fixture(
            json!({ "replicas": 3, "updateStrategy": { "type": "RollingUpdate" } }),
            json!({
                "observedGeneration": 3,
                "replicas": 3,
                "readyReplicas": 3,
                "updatedReplicas": 3,
                "currentRevision": "db-7",
                "updateRevision": "db-7",
            }),
        );
        assert_eq!(stateful_set(&settled).status, HealthStatus::Healthy);

        let stale = stateful_set_fixture(
            json!({ "replicas": 3 }),
            json!({
                "observedGeneration": 2,
                "replicas": 3,
                "readyReplicas": 3,
                "updatedReplicas": 3,
            }),
        );
        assert_eq!(stateful_set(&stale).status, HealthStatus::Progressing);
        assert_eq!(stateful_set(&stale).message, MSG_WAITING_FOR_OBSERVATION);
    }

    /// Trap: under `OnDelete` the controller never raises `updatedReplicas` by itself.
    #[test]
    fn an_ondelete_stateful_set_does_not_wait_for_updated_replicas() {
        let live = stateful_set_fixture(
            json!({ "replicas": 3, "updateStrategy": { "type": "OnDelete" } }),
            json!({
                "observedGeneration": 3,
                "replicas": 3,
                "readyReplicas": 3,
                // Stuck at the old revision: correct for OnDelete, healthy nonetheless.
                "updatedReplicas": 0,
                "currentRevision": "db-6",
                "updateRevision": "db-7",
            }),
        );
        let health = stateful_set(&live);
        assert_eq!(
            health.status,
            HealthStatus::Healthy,
            "an OnDelete StatefulSet must not hang waiting for updatedReplicas: {}",
            health.message
        );
        assert!(health.message.contains("OnDelete"), "{}", health.message);

        // Under OnDelete a pod that is not ready is still Progressing.
        let not_ready = stateful_set_fixture(
            json!({ "replicas": 3, "updateStrategy": { "type": "OnDelete" } }),
            json!({
                "observedGeneration": 3,
                "replicas": 3,
                "readyReplicas": 2,
                "updatedReplicas": 0,
            }),
        );
        assert_eq!(stateful_set(&not_ready).status, HealthStatus::Progressing);
    }

    /// Trap: a partitioned (`> 0`) rolling update only rolls `replicas - partition` ordinals.
    #[test]
    fn a_partitioned_stateful_set_only_requires_the_rolled_ordinals() {
        let live = stateful_set_fixture(
            json!({
                "replicas": 5,
                "updateStrategy": { "type": "RollingUpdate", "rollingUpdate": { "partition": 3 } },
            }),
            json!({
                "observedGeneration": 3,
                "replicas": 5,
                "readyReplicas": 5,
                // Only the 2 unpartitioned ordinals are expected to roll.
                "updatedReplicas": 2,
            }),
        );
        let health = stateful_set(&live);
        assert_eq!(health.status, HealthStatus::Healthy, "{}", health.message);
        assert!(health.message.contains("partition"), "{}", health.message);

        // A full partition asks for zero updates: readiness alone decides.
        let fully_pinned = stateful_set_fixture(
            json!({
                "replicas": 3,
                "updateStrategy": { "type": "RollingUpdate", "rollingUpdate": { "partition": 3 } },
            }),
            json!({
                "observedGeneration": 3,
                "replicas": 3,
                "readyReplicas": 3,
                "updatedReplicas": 0,
            }),
        );
        assert_eq!(stateful_set(&fully_pinned).status, HealthStatus::Healthy);

        // Without a partition the same counters are a stuck rollout.
        let unpartitioned = stateful_set_fixture(
            json!({ "replicas": 3 }),
            json!({
                "observedGeneration": 3,
                "replicas": 3,
                "readyReplicas": 3,
                "updatedReplicas": 0,
            }),
        );
        assert_eq!(
            stateful_set(&unpartitioned).status,
            HealthStatus::Progressing
        );

        // A partition of 3 of 5 replicas with only 1 rolled is still progressing.
        let partly = stateful_set_fixture(
            json!({
                "replicas": 5,
                "updateStrategy": { "type": "RollingUpdate", "rollingUpdate": { "partition": 3 } },
            }),
            json!({
                "observedGeneration": 3,
                "replicas": 5,
                "readyReplicas": 5,
                "updatedReplicas": 1,
            }),
        );
        assert_eq!(stateful_set(&partly).status, HealthStatus::Progressing);
    }

    #[test]
    fn a_stateful_set_scaled_to_zero_is_healthy() {
        let live = stateful_set_fixture(
            json!({ "replicas": 0 }),
            json!({ "observedGeneration": 3, "replicas": 0 }),
        );
        assert_eq!(stateful_set(&live).status, HealthStatus::Healthy);
    }

    // ---------------------------------------------------------------------
    // DaemonSet
    // ---------------------------------------------------------------------

    fn daemon_set_fixture(status: serde_json::Value) -> DynamicObject {
        object(json!({
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": { "name": "agent", "namespace": "payments", "generation": 4 },
            "spec": { "selector": { "matchLabels": { "app": "agent" } } },
            "status": status,
        }))
    }

    #[test]
    fn daemonset_health_tracks_desired_updated_and_available() {
        let healthy = daemon_set_fixture(json!({
            "observedGeneration": 4,
            "desiredNumberScheduled": 3,
            "updatedNumberScheduled": 3,
            "numberAvailable": 3,
            "numberReady": 3,
        }));
        assert_eq!(daemon_set(&healthy).status, HealthStatus::Healthy);

        let rolling = daemon_set_fixture(json!({
            "observedGeneration": 4,
            "desiredNumberScheduled": 3,
            "updatedNumberScheduled": 1,
            "numberAvailable": 3,
            "numberReady": 3,
        }));
        let health = daemon_set(&rolling);
        assert_eq!(health.status, HealthStatus::Progressing);
        assert!(health.message.contains("1/3 updated"), "{}", health.message);

        let unavailable = daemon_set_fixture(json!({
            "observedGeneration": 4,
            "desiredNumberScheduled": 2,
            "updatedNumberScheduled": 2,
            "numberAvailable": 1,
        }));
        assert_eq!(daemon_set(&unavailable).status, HealthStatus::Progressing);

        let stale = daemon_set_fixture(json!({
            "observedGeneration": 3,
            "desiredNumberScheduled": 3,
            "updatedNumberScheduled": 3,
            "numberAvailable": 3,
        }));
        assert_eq!(daemon_set(&stale).message, MSG_WAITING_FOR_OBSERVATION);

        // A selector that matches no node is not a failure.
        let no_nodes = daemon_set_fixture(json!({
            "observedGeneration": 4,
            "desiredNumberScheduled": 0,
        }));
        let health = daemon_set(&no_nodes);
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(health.message.contains("no node"), "{}", health.message);
    }

    // ---------------------------------------------------------------------
    // ReplicaSet
    // ---------------------------------------------------------------------

    fn replica_set_fixture(spec: serde_json::Value, status: serde_json::Value) -> DynamicObject {
        object(json!({
            "apiVersion": "apps/v1",
            "kind": "ReplicaSet",
            "metadata": { "name": "api-6f9", "namespace": "payments", "generation": 1 },
            "spec": spec,
            "status": status,
        }))
    }

    #[test]
    fn replicaset_health_needs_available_replicas_and_an_observed_generation() {
        let healthy = replica_set_fixture(
            json!({ "replicas": 2 }),
            json!({
                "observedGeneration": 1,
                "replicas": 2,
                "availableReplicas": 2,
                "readyReplicas": 2,
            }),
        );
        assert_eq!(replica_set(&healthy).status, HealthStatus::Healthy);

        let not_available = replica_set_fixture(
            json!({ "replicas": 2 }),
            json!({
                "observedGeneration": 1,
                "replicas": 2,
                "availableReplicas": 1,
            }),
        );
        assert_eq!(
            replica_set(&not_available).status,
            HealthStatus::Progressing
        );

        let stale = replica_set_fixture(
            json!({ "replicas": 2 }),
            json!({ "observedGeneration": 0, "replicas": 2, "availableReplicas": 2 }),
        );
        assert_eq!(replica_set(&stale).message, MSG_WAITING_FOR_OBSERVATION);

        let zero = replica_set_fixture(
            json!({ "replicas": 0 }),
            json!({ "observedGeneration": 1, "replicas": 0, "availableReplicas": 0 }),
        );
        assert_eq!(replica_set(&zero).status, HealthStatus::Healthy);
    }
}
