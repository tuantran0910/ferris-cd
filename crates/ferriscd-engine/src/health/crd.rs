//! Generic custom-resource health (`T09.4`): the `status.conditions` heuristic.
//!
//! A real cluster runs dozens of third-party CRDs (`Certificate`, `Database`, `VirtualService`,
//! `Cluster`), each from a different vendor, and none of them share a Go type. Almost all of them do
//! share one convention: a `status.conditions` list with a `True`/`False` verdict. This module turns
//! that convention into a health verdict without a line of per-CRD code.
//!
//! # Priority
//!
//! [`CONDITION_PRIORITY`] is `Ready`, `Available`, `Healthy`, `Synced`, in that order. The first
//! type that exists wins: cert-manager's `Certificate` publishes `Ready` and (in newer versions)
//! `Issuing`; Crossplane's managed resources publish `Ready`, `Synced`, and `Healthy`. `Ready` is
//! preferred because it is the type the Kubernetes ecosystem standardized on; `Available`/`Healthy`
//! cover controllers that predate it, and `Synced` is the weakest signal (a resource can be
//! perfectly synced with its provider and still unusable, which is exactly the
//! `Synced != Healthy` distinction `T09.5` guards).
//!
//! # Stale generations
//!
//! A controller that has not yet observed a `spec` edit still reports the *previous* `Ready=True`.
//! Reporting `Healthy` there hides a failing update until the next reconcile of the CR's own
//! controller — precisely the class of bug `observedGeneration` exists to prevent, so it is checked
//! in both places it can appear:
//!
//! * `status.observedGeneration` (the whole status is stale), and
//! * `condition.observedGeneration` (that individual condition is stale).
//!
//! Unlike the workload evaluators, a *missing* `observedGeneration` is not treated as stale here:
//! writing it is optional, and many well-behaved CRs never do. Treating it as stale would report
//! `Progressing` forever for every such CRD.
//!
//! # No conditions at all
//!
//! A spec-only CRD (a `ConfigMap`-shaped CR, a `Repository`/`Provider` config object) never writes
//! `status`. The default is therefore [`NoConditionPolicy::Healthy`]; a controller that expects
//! conditions from every CR can switch the whole registry to [`NoConditionPolicy::Unknown`] and make
//! the silence visible.

use kube::api::DynamicObject;

use super::values;
use super::{HealthConfig, MSG_WAITING_FOR_OBSERVATION, NoConditionPolicy, ResourceHealth};

/// Condition types consulted for an unrecognized kind, in priority order (`T09.4`).
pub const CONDITION_PRIORITY: [&str; 4] = ["Ready", "Available", "Healthy", "Synced"];

/// Reasons that mean "not finished yet" rather than "failed".
///
/// Matched case-insensitively. Keeping this list small and explicit is deliberate: a wrong entry
/// turns a real failure into an endless `Progressing`, while a missing entry only turns a transient
/// state into a (loud) `Degraded`.
pub const TRANSIENT_REASONS: [&str; 7] = [
    "Progressing",
    "Reconciling",
    "Pending",
    "InProgress",
    "Creating",
    "Updating",
    "Installing",
];

/// Returns whether `reason` marks a transient state.
#[must_use]
pub fn is_transient_reason(reason: &str) -> bool {
    let reason = reason.trim();
    TRANSIENT_REASONS
        .iter()
        .any(|transient| transient.eq_ignore_ascii_case(reason))
}

/// Generic condition-based health for any kind without a built-in evaluator.
#[must_use]
pub fn generic_crd_health(object: &DynamicObject, config: &HealthConfig) -> ResourceHealth {
    let conditions = values::conditions(object);

    // A whole-status staleness check: the CR's own controller has not observed this generation.
    // This runs before the no-conditions policy: a spec-only CR that still tracks
    // `status.observedGeneration` must not report Healthy for an unobserved edit.
    if let (Some(generation), Some(observed)) = (
        object.metadata.generation,
        values::int(object, &["status", "observedGeneration"]),
    ) && observed < generation
    {
        return ResourceHealth::progressing(MSG_WAITING_FOR_OBSERVATION);
    }

    if conditions.is_empty() {
        return match config.cr_without_conditions {
            NoConditionPolicy::Healthy => {
                ResourceHealth::healthy("custom resource is present (it reports no conditions)")
            }
            NoConditionPolicy::Unknown => ResourceHealth::unknown(
                "custom resource reports no status.conditions, so its health cannot be determined",
            ),
        };
    }

    let Some(condition) = CONDITION_PRIORITY
        .iter()
        .find_map(|type_| values::condition(&conditions, type_))
    else {
        return ResourceHealth::unknown(format!(
            "none of the {} conditions are present",
            CONDITION_PRIORITY.join("/")
        ));
    };

    // A stale *condition* is just as misleading as a stale status.
    if let (Some(generation), Some(observed)) =
        (object.metadata.generation, condition.observed_generation)
        && observed < generation
    {
        return ResourceHealth::progressing(format!(
            "{} condition has not observed generation {generation} yet",
            condition.type_
        ));
    }

    if condition.is_true() {
        return ResourceHealth::healthy(format!("{} condition is True", condition.type_));
    }

    if condition.is_false() {
        return if is_transient_reason(condition.reason) {
            ResourceHealth::progressing(format!(
                "{} condition is False ({})",
                condition.type_,
                condition.describe()
            ))
        } else {
            ResourceHealth::degraded(format!(
                "{} condition is False ({})",
                condition.type_,
                condition.describe()
            ))
        };
    }

    // `status: Unknown`, an empty `status`, or anything else: not settled, but not a failure.
    ResourceHealth::progressing(format!(
        "{} condition is {}",
        condition.type_,
        if condition.status.is_empty() {
            "unset"
        } else {
            condition.status
        }
    ))
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

    /// A real cert-manager `Certificate`, trimmed to the fields the heuristic reads.
    #[test]
    fn a_certmanager_certificate_ready_condition_decides_its_health() {
        let ready = object(json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "web-tls", "namespace": "payments", "generation": 3 },
            "spec": { "secretName": "web-tls", "dnsNames": ["web.example.com"] },
            "status": {
                "observedGeneration": 3,
                "conditions": [
                    { "type": "Ready", "status": "True", "reason": "Ready",
                      "message": "Certificate is up to date and has not expired",
                      "observedGeneration": 3 },
                    { "type": "Issuing", "status": "False", "reason": "DoesNotExist" }
                ],
            },
        }));
        assert_eq!(
            generic_crd_health(&ready, &config()).status,
            HealthStatus::Healthy
        );

        let not_ready = object(json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "web-tls", "namespace": "payments", "generation": 4 },
            "status": {
                "observedGeneration": 4,
                "conditions": [{
                    "type": "Ready",
                    "status": "False",
                    "reason": "DoesNotExist",
                    "message": "Issuing certificate as Secret does not exist",
                }],
            },
        }));
        let health = generic_crd_health(&not_ready, &config());
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("DoesNotExist"),
            "{}",
            health.message
        );

        // A transient reason is converging, not broken.
        let reconciling = object(json!({
            "apiVersion": "cert-manager.io/v1",
            "kind": "Certificate",
            "metadata": { "name": "web-tls", "namespace": "payments" },
            "status": { "conditions": [{
                "type": "Ready", "status": "False", "reason": "Reconciling",
            }] },
        }));
        assert_eq!(
            generic_crd_health(&reconciling, &config()).status,
            HealthStatus::Progressing
        );
    }

    /// A Crossplane managed resource publishes `Ready`, `Synced` and `Healthy`.
    #[test]
    fn a_crossplane_resource_prefers_ready_over_synced() {
        // Synced=True but Ready=False (the provider accepted the spec and the cloud call failed):
        // `Ready` wins, so the verdict is Degraded. Reversing this would report a broken database
        // as healthy because GitOps was happy.
        let live = object(json!({
            "apiVersion": "rds.aws.crossplane.io/v1alpha1",
            "kind": "DBInstance",
            "metadata": { "name": "orders", "namespace": "payments", "generation": 2 },
            "status": {
                "observedGeneration": 2,
                "conditions": [
                    { "type": "Synced", "status": "True", "reason": "ReconcileSuccess",
                      "observedGeneration": 2 },
                    { "type": "Ready", "status": "False", "reason": "Unavailable",
                      "message": "cannot create DB instance: access denied",
                      "observedGeneration": 2 }
                ],
            },
        }));
        let health = generic_crd_health(&live, &config());
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("access denied"),
            "the provider's message must be surfaced: {}",
            health.message
        );

        // Only a `Synced` condition (a `ProviderConfig`, which has no `Ready`): Synced is the last
        // resort and still decides.
        let synced_only = object(json!({
            "apiVersion": "aws.crossplane.io/v1beta1",
            "kind": "ProviderConfig",
            "metadata": { "name": "default" },
            "status": { "conditions": [
                { "type": "Synced", "status": "True", "reason": "ReconcileSuccess" },
            ] },
        }));
        assert_eq!(
            generic_crd_health(&synced_only, &config()).status,
            HealthStatus::Healthy
        );
    }

    #[test]
    fn a_spec_only_custom_resource_is_healthy_by_default_and_configurable() {
        let spec_only = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one", "namespace": "payments" },
            "spec": { "size": 3 },
        }));
        assert_eq!(
            generic_crd_health(&spec_only, &config()).status,
            HealthStatus::Healthy
        );

        let strict = HealthConfig {
            cr_without_conditions: NoConditionPolicy::Unknown,
            ..HealthConfig::default()
        };
        let health = generic_crd_health(&spec_only, &strict);
        assert_eq!(health.status, HealthStatus::Unknown);
        assert!(
            health.message.contains("no status.conditions"),
            "{}",
            health.message
        );
    }

    /// Trap guard: a stale `Ready=True` must not mask an edit the controller has not observed.
    #[test]
    fn a_stale_generation_beats_a_ready_true_condition() {
        let stale_status = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one", "namespace": "payments", "generation": 7 },
            "status": {
                "observedGeneration": 6,
                "conditions": [{ "type": "Ready", "status": "True", "reason": "Available" }],
            },
        }));
        let health = generic_crd_health(&stale_status, &config());
        assert_eq!(health.status, HealthStatus::Progressing);
        assert_eq!(health.message, MSG_WAITING_FOR_OBSERVATION);

        // A spec-only CR that tracks generation but publishes no conditions is still stale.
        let stale_without_conditions = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one", "namespace": "payments", "generation": 7 },
            "status": { "observedGeneration": 6 },
        }));
        let health = generic_crd_health(&stale_without_conditions, &config());
        assert_eq!(health.status, HealthStatus::Progressing);
        assert_eq!(health.message, MSG_WAITING_FOR_OBSERVATION);

        // Stale *condition*: the status is current but the condition is not.
        let stale_condition = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one", "namespace": "payments", "generation": 7 },
            "status": {
                "observedGeneration": 7,
                "conditions": [{
                    "type": "Ready", "status": "True", "reason": "Available",
                    "observedGeneration": 5,
                }],
            },
        }));
        let health = generic_crd_health(&stale_condition, &config());
        assert_eq!(health.status, HealthStatus::Progressing);
        assert!(
            health.message.contains("generation 7"),
            "{}",
            health.message
        );

        // An *absent* `observedGeneration` is not stale: many controllers never write one.
        let no_generation = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one", "namespace": "payments", "generation": 7 },
            "status": { "conditions": [{ "type": "Ready", "status": "True" }] },
        }));
        assert_eq!(
            generic_crd_health(&no_generation, &config()).status,
            HealthStatus::Healthy
        );
    }

    #[test]
    fn unrecognized_conditions_and_unknown_statuses_are_reported_honestly() {
        let no_priority_type = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one" },
            "status": { "conditions": [{ "type": "Paused", "status": "True" }] },
        }));
        let health = generic_crd_health(&no_priority_type, &config());
        assert_eq!(health.status, HealthStatus::Unknown);
        assert!(
            health.message.contains("Ready/Available/Healthy/Synced"),
            "{}",
            health.message
        );

        let unknown_status = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one" },
            "status": { "conditions": [{ "type": "Ready", "status": "Unknown" }] },
        }));
        let health = generic_crd_health(&unknown_status, &config());
        assert_eq!(health.status, HealthStatus::Progressing);
        assert!(health.message.contains("Unknown"), "{}", health.message);
    }

    #[test]
    fn transient_reasons_match_case_insensitively_and_only_when_listed() {
        for reason in [
            "Progressing",
            "reconciling",
            " RECONCILING ",
            "Pending",
            "Installing",
        ] {
            assert!(is_transient_reason(reason), "{reason:?} must be transient");
        }
        for reason in [
            "",
            "ReconcileFailed",
            "InvalidConfig",
            "BackoffLimitExceeded",
        ] {
            assert!(
                !is_transient_reason(reason),
                "{reason:?} must not be transient"
            );
        }
    }
}
