//! Runtime resource health (`T09.3`): `Pod`, `Job`, `Service`, `Ingress`, `PersistentVolumeClaim`.
//!
//! Three traps live here:
//!
//! * **A `Job` retry is not a failure.** A `Job` with `backoffLimit: 6` reports `status.failed: 1`
//!   while it is still retrying inside its own budget. Only `conditions[type=Failed, status=True]`
//!   means the `Job` gave up; treating `status.failed > 0` as `Degraded` fails a sync wave that a
//!   `PreSync` migration would have completed seconds later (`T09.3` trap guard).
//! * **`ImagePullBackOff`/`CrashLoopBackOff` are `Degraded`, not `Progressing`.** The pod is
//!   `Running`/`Pending` with a container that will *never* start without a human changing the
//!   image or the config, so reporting "still converging" hides the failure behind an infinite
//!   rollout.
//! * **`LoadBalancer` on a cluster without a load-balancer controller** (every `kind` cluster):
//!   `status.loadBalancer.ingress` stays empty forever. The default is still
//!   [`LoadBalancerPolicy::RequireIngress`] — a cloud `Service` really is not serving before it has
//!   an address — but the verdict is configurable per object with the
//!   [`LOAD_BALANCER_HEALTH_ANNOTATION`] annotation and globally with
//!   [`HealthConfig::load_balancer`].
//!
//! `Ingress` and `PersistentVolumeClaim` complete the set: a `PVC` is `Bound`/`Lost`/`Pending`, and
//! an `Ingress` has no trustworthy condition surface at all (its `status.loadBalancer` is about a
//! controller-specific address, and an `Ingress` with a broken backend is still `Accepted`).

use kube::api::DynamicObject;

use super::values;
use super::{HealthConfig, HealthEvaluator, ResourceHealth};

/// Per-object override of how a `Service: LoadBalancer` is judged.
///
/// Annotations live on the *live* object (not on the `Application`), so a single chart can mark one
/// local-only `Service` while every other `LoadBalancer` keeps the production default.
pub const LOAD_BALANCER_HEALTH_ANNOTATION: &str = "ferriscd.io/load-balancer-health";

/// Container waiting reasons that will never resolve without a human (`T09.3`).
pub const FATAL_WAITING_REASONS: [&str; 4] = [
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "CreateContainerConfigError",
];

/// How a `Service` of type `LoadBalancer` is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadBalancerPolicy {
    /// `Healthy` only once `status.loadBalancer.ingress` is non-empty (production default).
    RequireIngress,
    /// `Healthy` as soon as the object exists (local clusters without a load-balancer controller).
    Ignore,
}

impl LoadBalancerPolicy {
    /// Parses the annotation value; `None` for an unrecognized value.
    ///
    /// Accepted spellings are deliberately small: a typo must not silently disable the check.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ignore" | "ignored" | "healthy" | "none" => Some(Self::Ignore),
            "require" | "wait" | "ingress" | "default" => Some(Self::RequireIngress),
            _ => None,
        }
    }

    /// The annotation value of this policy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequireIngress => "Require",
            Self::Ignore => "Ignore",
        }
    }
}

/// `Pod` health (`T09.3`).
#[derive(Debug, Clone, Copy)]
pub struct PodHealth;

impl HealthEvaluator for PodHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        pod(object)
    }
}

/// `Pod` health, exposed as a pure function.
///
/// * `Succeeded` → `Healthy`, `Failed` → `Degraded` (both are terminal, so they are decided first:
///   a completed pod's container can legitimately carry an `Error`/`OOMKilled` terminated state).
/// * A container waiting in a [`FATAL_WAITING_REASONS`] state → `Degraded`, whatever the phase.
/// * `Running` + `Ready=True` → `Healthy`; anything else → `Progressing`.
#[must_use]
pub fn pod(object: &DynamicObject) -> ResourceHealth {
    let phase = values::text(object, &["status", "phase"]).unwrap_or_default();

    match phase {
        "Succeeded" => return ResourceHealth::healthy("Pod completed successfully"),
        "Failed" => {
            let reason = values::text(object, &["status", "reason"]).unwrap_or_default();
            let message = values::text(object, &["status", "message"]).unwrap_or_default();
            return ResourceHealth::degraded(format!("Pod failed{}", describe(reason, message)));
        }
        _ => {}
    }

    if let Some(fatal) = fatal_waiting_container(object) {
        return ResourceHealth::degraded(fatal);
    }

    if phase.is_empty() {
        return ResourceHealth::progressing("Pod has not reported a status.phase yet");
    }

    if phase == "Running" {
        if ready_condition(object) {
            return ResourceHealth::healthy("Pod is running and Ready");
        }
        return ResourceHealth::progressing("Pod is running but not Ready");
    }

    ResourceHealth::progressing(format!("Pod is {phase}"))
}

/// Returns a `Degraded` message when any container is waiting in a fatal state.
///
/// `initContainerStatuses` is checked too: a `PreSync`-style init container that cannot fetch its
/// configuration is exactly the wedge an operator needs to see.
fn fatal_waiting_container(object: &DynamicObject) -> Option<String> {
    for group in ["initContainerStatuses", "containerStatuses"] {
        for status in values::entries(object, &["status", group]) {
            let reason = status
                .get("state")
                .and_then(|state| state.get("waiting"))
                .and_then(|waiting| waiting.get("reason"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if FATAL_WAITING_REASONS.contains(&reason) {
                let name = status
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("container");
                return Some(format!("container {name} is waiting: {reason}"));
            }
        }
    }
    None
}

/// Returns whether the `Ready` condition is `True`.
fn ready_condition(object: &DynamicObject) -> bool {
    let conditions = values::conditions(object);
    values::condition(&conditions, "Ready").is_some_and(|condition| condition.is_true())
}

/// `reason`/`message` suffix for a failure message.
fn describe(reason: &str, message: &str) -> String {
    match (reason.is_empty(), message.is_empty()) {
        (false, false) => format!(" ({reason}: {message})"),
        (false, true) => format!(" ({reason})"),
        (true, false) => format!(" ({message})"),
        (true, true) => String::new(),
    }
}

/// `Job` health (`T09.3`).
#[derive(Debug, Clone, Copy)]
pub struct JobHealth;

impl HealthEvaluator for JobHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        job(object)
    }
}

/// `Job` health, exposed as a pure function.
///
/// The trap is the last branch: `status.failed > 0` on its own is a **normal retry**. Kubernetes
/// increments it for every failed pod attempt while `backoffLimit` (default 6) still allows another
/// try, so a `Job` one second into its second attempt is `Progressing`, not `Degraded`.
#[must_use]
pub fn job(object: &DynamicObject) -> ResourceHealth {
    if values::flag(object, &["spec", "suspend"]).unwrap_or(false) {
        return ResourceHealth::suspended("Job is suspended (spec.suspend=true)");
    }

    let conditions = values::conditions(object);
    if values::condition(&conditions, "Complete").is_some_and(|condition| condition.is_true()) {
        return ResourceHealth::healthy("Job completed successfully");
    }
    if let Some(failed) = values::condition(&conditions, "Failed")
        && failed.is_true()
    {
        return ResourceHealth::degraded(format!("Job failed ({})", failed.describe()));
    }

    let active = values::count(object, &["status", "active"]);
    let succeeded = values::count(object, &["status", "succeeded"]);
    let failed = values::count(object, &["status", "failed"]);
    ResourceHealth::progressing(format!(
        "Job has not completed yet: {active} active, {succeeded} succeeded, {failed} failed attempt(s)"
    ))
}

/// `Service` health (`T09.3`).
#[derive(Debug, Clone, Copy)]
pub struct ServiceHealth;

impl HealthEvaluator for ServiceHealth {
    fn evaluate(&self, object: &DynamicObject, config: &HealthConfig) -> ResourceHealth {
        service(object, config)
    }
}

/// `Service` health, exposed as a pure function.
///
/// `ClusterIP`, `NodePort` and `ExternalName` services are addressable as soon as they exist (they
/// have no provisioning step), so they are `Healthy`. A `LoadBalancer` is `Healthy` only once the
/// provider has published an address — unless the object opts out with
/// [`LOAD_BALANCER_HEALTH_ANNOTATION`] or the whole controller does with
/// [`HealthConfig::load_balancer`].
#[must_use]
pub fn service(object: &DynamicObject, config: &HealthConfig) -> ResourceHealth {
    let service_type = values::text(object, &["spec", "type"]).unwrap_or("ClusterIP");
    if service_type != "LoadBalancer" {
        return ResourceHealth::healthy(format!("Service is of type {service_type}"));
    }

    let policy = annotation_policy(object).unwrap_or(config.load_balancer);
    if policy == LoadBalancerPolicy::Ignore {
        return ResourceHealth::healthy(
            "LoadBalancer Service exists (load-balancer address is not required here)",
        );
    }

    if !values::entries(object, &["status", "loadBalancer", "ingress"]).is_empty() {
        return ResourceHealth::healthy("LoadBalancer Service has an ingress address");
    }

    ResourceHealth::progressing(
        "waiting for the load balancer to be provisioned (status.loadBalancer.ingress is empty)",
    )
}

/// Reads the per-object load-balancer policy annotation.
fn annotation_policy(object: &DynamicObject) -> Option<LoadBalancerPolicy> {
    let raw = object
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(LOAD_BALANCER_HEALTH_ANNOTATION))?;
    LoadBalancerPolicy::parse(raw)
}

/// `Ingress` health (`T09.3`).
///
/// An `Ingress` has no condition type FerrisCD can trust: `status.loadBalancer.ingress` is
/// controller-specific, and an `Ingress` pointing at a dead `Service` is still accepted by the API
/// server and by every ingress controller. Health therefore reports "the object exists" and leaves
/// the backend's health to the `Service`/`Pod` that *does* have a status surface. This is the same
/// reading Argo CD uses for kinds with no health check (the resource is `Healthy` when it exists).
#[derive(Debug, Clone, Copy)]
pub struct IngressHealth;

impl HealthEvaluator for IngressHealth {
    fn evaluate(&self, _object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        ResourceHealth::healthy("Ingress exists")
    }
}

/// `PersistentVolumeClaim` health (`T09.3`).
#[derive(Debug, Clone, Copy)]
pub struct PersistentVolumeClaimHealth;

impl HealthEvaluator for PersistentVolumeClaimHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        persistent_volume_claim(object)
    }
}

/// `PersistentVolumeClaim` health: `Bound` → `Healthy`, `Lost` → `Degraded`, `Pending` →
/// `Progressing`.
#[must_use]
pub fn persistent_volume_claim(object: &DynamicObject) -> ResourceHealth {
    match values::text(object, &["status", "phase"]).unwrap_or_default() {
        "Bound" => ResourceHealth::healthy("PersistentVolumeClaim is bound"),
        "Lost" => ResourceHealth::degraded(
            "PersistentVolumeClaim lost its PersistentVolume (the volume is gone)",
        ),
        "Pending" => ResourceHealth::progressing("waiting for a PersistentVolume to be bound"),
        "" => ResourceHealth::progressing("PersistentVolumeClaim has not been bound yet"),
        other => ResourceHealth::progressing(format!("PersistentVolumeClaim is {other}")),
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

    fn config() -> HealthConfig {
        HealthConfig::default()
    }

    fn pod_fixture(status: serde_json::Value) -> DynamicObject {
        object(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "api-6f9-x2", "namespace": "payments" },
            "spec": { "containers": [{ "name": "api", "image": "example.com/api:1" }] },
            "status": status,
        }))
    }

    // ---------------------------------------------------------------------
    // Pod
    // ---------------------------------------------------------------------

    #[test]
    fn a_running_ready_pod_is_healthy_and_a_non_ready_pod_is_progressing() {
        let ready = pod_fixture(json!({
            "phase": "Running",
            "conditions": [{ "type": "Ready", "status": "True" }],
        }));
        assert_eq!(pod(&ready).status, HealthStatus::Healthy);

        let not_ready = pod_fixture(json!({
            "phase": "Running",
            "conditions": [{ "type": "Ready", "status": "False", "reason": "ContainersNotReady" }],
        }));
        let health = pod(&not_ready);
        assert_eq!(health.status, HealthStatus::Progressing);
        assert!(health.message.contains("not Ready"), "{}", health.message);

        let pending = pod_fixture(json!({ "phase": "Pending" }));
        assert_eq!(pod(&pending).status, HealthStatus::Progressing);
        assert!(pod(&pending).message.contains("Pending"));

        let no_status = pod_fixture(json!({}));
        assert_eq!(pod(&no_status).status, HealthStatus::Progressing);
    }

    #[test]
    fn terminal_pod_phases_decide_before_anything_else() {
        let succeeded = pod_fixture(json!({
            "phase": "Succeeded",
            "containerStatuses": [{
                "name": "api",
                "state": { "terminated": { "exitCode": 0 } },
            }],
        }));
        assert_eq!(pod(&succeeded).status, HealthStatus::Healthy);

        let failed = pod_fixture(json!({
            "phase": "Failed",
            "reason": "Evicted",
            "message": "The node was low on resource: memory.",
        }));
        let health = pod(&failed);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(health.message.contains("Evicted"), "{}", health.message);
    }

    #[test]
    fn every_fatal_container_waiting_reason_is_degraded() {
        for reason in FATAL_WAITING_REASONS {
            let live = pod_fixture(json!({
                "phase": "Running",
                "containerStatuses": [{
                    "name": "api",
                    "ready": false,
                    "state": { "waiting": { "reason": reason, "message": "back-off 10s" } },
                    "restartCount": 4,
                }],
            }));
            let health = pod(&live);
            assert_eq!(
                health.status,
                HealthStatus::Degraded,
                "{reason} must be Degraded, not an endless Progressing"
            );
            assert!(
                health.message.contains(reason) && health.message.contains("api"),
                "{}",
                health.message
            );
        }

        // A non-fatal waiting reason (a container image still being pulled) stays Progressing.
        let pulling = pod_fixture(json!({
            "phase": "Pending",
            "containerStatuses": [{
                "name": "api",
                "state": { "waiting": { "reason": "ContainerCreating" } },
            }],
        }));
        assert_eq!(pod(&pulling).status, HealthStatus::Progressing);
    }

    #[test]
    fn an_init_container_waiting_fatally_is_degraded_too() {
        let live = pod_fixture(json!({
            "phase": "Pending",
            "initContainerStatuses": [{
                "name": "migrate",
                "state": { "waiting": { "reason": "CreateContainerConfigError" } },
            }],
        }));
        let health = pod(&live);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(health.message.contains("migrate"), "{}", health.message);
    }

    // ---------------------------------------------------------------------
    // Job
    // ---------------------------------------------------------------------

    fn job_fixture(spec: serde_json::Value, status: serde_json::Value) -> DynamicObject {
        object(json!({
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": { "name": "migrate", "namespace": "payments", "generation": 1 },
            "spec": spec,
            "status": status,
        }))
    }

    #[test]
    fn job_suspend_complete_and_failed_conditions_are_authoritative() {
        let suspended = job_fixture(
            json!({ "suspend": true }),
            json!({ "active": 0, "failed": 0 }),
        );
        assert_eq!(job(&suspended).status, HealthStatus::Suspended);

        let complete = job_fixture(
            json!({}),
            json!({
                "succeeded": 1,
                "conditions": [{ "type": "Complete", "status": "True", "reason": "CompletionsReached" }],
            }),
        );
        assert_eq!(job(&complete).status, HealthStatus::Healthy);

        let failed = job_fixture(
            json!({}),
            json!({
                "failed": 3,
                "conditions": [{
                    "type": "Failed",
                    "status": "True",
                    "reason": "BackoffLimitExceeded",
                    "message": "Job has reached the specified backoff limit",
                }],
            }),
        );
        let health = job(&failed);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("BackoffLimitExceeded"),
            "{}",
            health.message
        );
    }

    /// `T09.3` trap guard: a retrying `Job` is `Progressing`, never `Degraded`.
    #[test]
    fn a_retrying_job_with_status_failed_is_progressing() {
        let retrying = job_fixture(
            json!({ "backoffLimit": 6 }),
            json!({
                "active": 1,
                "failed": 1,
                "conditions": [{ "type": "FailureTarget", "status": "True" }],
            }),
        );
        let health = job(&retrying);
        assert_eq!(
            health.status,
            HealthStatus::Progressing,
            "status.failed > 0 without a Failed condition is a normal retry: {}",
            health.message
        );
        assert!(
            health.message.contains("1 failed attempt(s)"),
            "the retry must still be visible: {}",
            health.message
        );

        // A `Failed=False` condition is not a failure either.
        let not_failed = job_fixture(
            json!({}),
            json!({
                "active": 1,
                "conditions": [{ "type": "Failed", "status": "False" }],
            }),
        );
        assert_eq!(job(&not_failed).status, HealthStatus::Progressing);

        // A brand-new Job with no status at all is still converging.
        assert_eq!(
            job(&job_fixture(json!({}), json!({}))).status,
            HealthStatus::Progressing
        );
    }

    // ---------------------------------------------------------------------
    // Service
    // ---------------------------------------------------------------------

    fn service_fixture(service_type: &str, status: serde_json::Value) -> DynamicObject {
        object(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "api", "namespace": "payments" },
            "spec": { "type": service_type },
            "status": status,
        }))
    }

    #[test]
    fn addressable_service_types_are_healthy_and_a_loadbalancer_waits_for_an_address() {
        for service_type in ["ClusterIP", "NodePort", "ExternalName"] {
            let live = service_fixture(service_type, json!({}));
            assert_eq!(
                service(&live, &config()).status,
                HealthStatus::Healthy,
                "{service_type} needs no provisioning"
            );
        }

        // An absent `spec.type` means ClusterIP.
        let defaulted = object(json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": { "name": "api" },
        }));
        assert_eq!(service(&defaulted, &config()).status, HealthStatus::Healthy);

        let pending = service_fixture("LoadBalancer", json!({ "loadBalancer": {} }));
        let health = service(&pending, &config());
        assert_eq!(health.status, HealthStatus::Progressing);
        assert!(
            health.message.contains("waiting for the load balancer"),
            "{}",
            health.message
        );

        let provisioned = service_fixture(
            "LoadBalancer",
            json!({ "loadBalancer": { "ingress": [{ "ip": "10.0.0.5" }] } }),
        );
        assert_eq!(
            service(&provisioned, &config()).status,
            HealthStatus::Healthy
        );
    }

    #[test]
    fn the_load_balancer_verdict_is_configurable_per_object_and_per_controller() {
        let pending = service_fixture("LoadBalancer", json!({ "loadBalancer": {} }));

        // Global option: a local cluster with no LB controller.
        let local = HealthConfig {
            load_balancer: LoadBalancerPolicy::Ignore,
            ..HealthConfig::default()
        };
        assert_eq!(service(&pending, &local).status, HealthStatus::Healthy);

        // Per-object annotation wins over the global default.
        let mut annotated = pending.clone();
        annotated
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                LOAD_BALANCER_HEALTH_ANNOTATION.to_owned(),
                "Ignore".to_owned(),
            );
        assert_eq!(service(&annotated, &config()).status, HealthStatus::Healthy);
        assert_eq!(
            service(&annotated, &local).status,
            HealthStatus::Healthy,
            "the annotation and the option agree"
        );

        // The annotation can also tighten the default back, and a typo is ignored (not fatal).
        let mut strict = pending.clone();
        strict
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                LOAD_BALANCER_HEALTH_ANNOTATION.to_owned(),
                "require".to_owned(),
            );
        assert_eq!(service(&strict, &local).status, HealthStatus::Progressing);

        let mut typo = pending;
        typo.metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                LOAD_BALANCER_HEALTH_ANNOTATION.to_owned(),
                "ignroe".to_owned(),
            );
        assert_eq!(
            service(&typo, &config()).status,
            HealthStatus::Progressing,
            "an unparseable annotation must fall back to the default, never silently disable the check"
        );

        assert_eq!(
            LoadBalancerPolicy::parse("IGNORE"),
            Some(LoadBalancerPolicy::Ignore)
        );
        assert_eq!(
            LoadBalancerPolicy::parse("wait"),
            Some(LoadBalancerPolicy::RequireIngress)
        );
        assert_eq!(LoadBalancerPolicy::parse("yes"), None);
        assert_eq!(LoadBalancerPolicy::Ignore.as_str(), "Ignore");
        assert_eq!(LoadBalancerPolicy::RequireIngress.as_str(), "Require");
    }

    // ---------------------------------------------------------------------
    // Ingress & PVC
    // ---------------------------------------------------------------------

    #[test]
    fn an_ingress_is_healthy_when_it_exists() {
        let live = object(json!({
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": { "name": "web", "namespace": "payments" },
            "spec": { "rules": [] },
            "status": { "loadBalancer": {} },
        }));
        assert_eq!(
            IngressHealth.evaluate(&live, &config()).status,
            HealthStatus::Healthy
        );
    }

    #[test]
    fn pvc_phases_map_onto_the_lattice() {
        let cases = [
            ("Bound", HealthStatus::Healthy),
            ("Lost", HealthStatus::Degraded),
            ("Pending", HealthStatus::Progressing),
            ("", HealthStatus::Progressing),
        ];
        for (phase, expected) in cases {
            let live = object(json!({
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": { "name": "data", "namespace": "payments" },
                "spec": { "accessModes": ["ReadWriteOnce"] },
                "status": { "phase": phase },
            }));
            assert_eq!(
                persistent_volume_claim(&live).status,
                expected,
                "PVC phase {phase:?}"
            );
        }
    }
}
