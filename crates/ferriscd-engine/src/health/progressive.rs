//! Progressive-delivery health (`T20.3`): Gateway API `HTTPRoute`, Argo Rollouts `Rollout`, and
//! Flagger `Canary`.
//!
//! A canary that is "synced" is not a canary that is serving. All three controllers publish the
//! rollout's own verdict in `status`, and all three spell it differently — which is exactly why a
//! generic `Ready`-condition heuristic is not enough: an Argo `Rollout` in `Paused` and a Flagger
//! `Canary` in `Waiting` are *intentionally* not finished (a wave gate that treats them as broken
//! would fail a healthy canary on its wave timeout), while a `Degraded` rollout must fail the wave
//! immediately instead of burning ten minutes of timeout.
//!
//! | Kind | Source of truth | `Healthy` | `Progressing` | `Suspended` | `Degraded` |
//! |---|---|---|---|---|---|
//! | `gateway.networking.k8s.io/HTTPRoute` | `status.parents[].conditions` | every parent `Accepted=True` **and** `ResolvedRefs=True` | a parent condition missing/`Unknown`/stale | — | any parent `Accepted=False` / `ResolvedRefs=False` |
//! | `argoproj.io/Rollout` | `status.phase` | `Healthy` | `Progressing` | `Paused` | `Degraded`, `InvalidSpec=True` |
//! | `flagger.app/Canary` | `status.phase` | `Initialized`, `Succeeded`, `Finalized` | `Initializing`, `Waiting`, `Progressing`, `Promoting`, `Finalizing`, `Terminating` | — | `Failed` |
//!
//! # Stale `observedGeneration`
//!
//! Every evaluator checks `observedGeneration` **first**, and a stale one is `Progressing`, never
//! `Healthy` (the `T09.2` rule, restated here because it is the trap that matters most for
//! progressive delivery): a `Rollout` whose `spec` just changed still reports the *previous*
//! `Healthy`, and promoting a wave on that verdict ships the new revision to 100% of traffic without
//! a single canary sample.
//!
//! The staleness check has two halves, matching where each controller writes the field:
//! `status.observedGeneration` (Argo `Rollout`, Flagger `Canary`, and — in newer Gateway API
//! revisions — `HTTPRoute`) and `status.parents[].conditions[].observedGeneration` (the Gateway API
//! condition-level form). Both halves accept the generation written as a JSON **number or a decimal
//! string**, because Argo Rollouts publishes `"observedGeneration": "3"` through an unstructured
//! object: reading only the numeric form left the guard dead (`T20.3` finding H3). An *absent*
//! `observedGeneration` is never treated as stale here (writing it is optional for a `Canary`), so a
//! controller that never sets it keeps working.
//!
//! # Purity
//!
//! These evaluators are pure readers of the live object's `status`: no API call, no clock, no
//! logging, no Prometheus. Metric-gated promotion (`T20.3`) is a *separate* mechanism that lives in
//! the controller and runs through the persisted `status.operationState`; nothing here issues a
//! query, so evaluating health can never block a reconcile worker on a metrics backend.

use kube::api::DynamicObject;
use serde_json::Value;

use super::values;
use super::{
    HealthConfig, HealthEvaluator, MSG_WAITING_FOR_OBSERVATION, ResourceHealth, precedence,
};

/// API group of the Gateway API route kinds.
pub const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

/// API group of Argo Rollouts.
pub const ARGO_ROLLOUT_GROUP: &str = "argoproj.io";

/// API group of Flagger.
pub const FLAGGER_GROUP: &str = "flagger.app";

/// The parent conditions a `HTTPRoute` must satisfy (`T20.3`).
///
/// `Accepted` says the gateway took ownership of the route; `ResolvedRefs` says every
/// `backendRef`/`secretRef` of the route resolves. A route with `Accepted=True` and
/// `ResolvedRefs=False` is accepted but routes to nothing — reporting it `Healthy` is the false
/// green this list exists to prevent.
pub const ROUTE_PARENT_CONDITIONS: [&str; 2] = ["Accepted", "ResolvedRefs"];

/// `Rollout.status.phase` values Argo Rollouts publishes.
pub const ROLLOUT_PHASES: [&str; 4] = ["Healthy", "Progressing", "Paused", "Degraded"];

/// Flagger `Canary.status.phase` values that mean the canary finished successfully.
pub const CANARY_HEALTHY_PHASES: [&str; 3] = ["Initialized", "Succeeded", "Finalized"];

/// Flagger `Canary.status.phase` values that mean the canary is still converging.
///
/// `Waiting` and `Promoting` are the bake and the traffic shift; treating either as finished would
/// promote the next wave before the canary ever saw production traffic. `Finalizing` and
/// `Terminating` are Flagger's own **wire spellings** (`CanaryPhaseFinalizing`,
/// `CanaryPhaseTerminating`) — note the American `-izing`: a list carrying the British
/// `Finalising` matches nothing a real canary ever reports, so a *successful* production canary was
/// reported `Unknown` and burned the whole wave timeout (`T20.3` finding H2). `Terminating` is
/// converging rather than `Degraded`: Flagger is deleting the canary's resources, which is not a
/// regression and must not fail the wave.
pub const CANARY_PROGRESSING_PHASES: [&str; 6] = [
    "Initializing",
    "Waiting",
    "Progressing",
    "Promoting",
    "Finalizing",
    "Terminating",
];

/// Flagger `Canary.status.phase` values that mean the canary gave up.
pub const CANARY_DEGRADED_PHASES: [&str; 1] = ["Failed"];

/// Health of a Gateway API `HTTPRoute` (`T20.3`).
#[derive(Debug, Clone, Copy)]
pub struct HttpRouteHealth;

impl HealthEvaluator for HttpRouteHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        http_route(object)
    }
}

/// Health of an Argo Rollouts `Rollout` (`T20.3`).
#[derive(Debug, Clone, Copy)]
pub struct RolloutHealth;

impl HealthEvaluator for RolloutHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        argo_rollout(object)
    }
}

/// Health of a Flagger `Canary` (`T20.3`).
#[derive(Debug, Clone, Copy)]
pub struct CanaryHealth;

impl HealthEvaluator for CanaryHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        flagger_canary(object)
    }
}

/// Returns whether `observed` is behind `generation` (both must be known).
fn is_stale(generation: Option<i64>, observed: Option<i64>) -> bool {
    matches!((generation, observed), (Some(generation), Some(observed)) if observed < generation)
}

/// Whether `object.status.observedGeneration` lags `metadata.generation`.
///
/// Accepts the generation as a number or as a decimal string (`T20.3` finding H3): Argo Rollouts
/// writes `"observedGeneration": "3"` through an unstructured object, so the numeric-only read used
/// to return `None` — i.e. "unknown", which is never stale — and the guard was dead against exactly
/// the controller it exists for.
fn status_is_stale(object: &DynamicObject) -> bool {
    is_stale(
        object.metadata.generation,
        values::int_or_numeric_string(object, &["status", "observedGeneration"]),
    )
}

/// `HTTPRoute` health from `status.parents[].conditions` (`T20.3`).
///
/// A route can be attached to several gateways, and one gateway accepting it does not mean the
/// others did: the verdict is the **worst** parent, so a route a second gateway rejected cannot be
/// reported `Healthy` because the first one is fine.
#[must_use]
pub fn http_route(object: &DynamicObject) -> ResourceHealth {
    if status_is_stale(object) {
        return ResourceHealth::progressing(MSG_WAITING_FOR_OBSERVATION);
    }

    let parents = values::entries(object, &["status", "parents"]);
    if parents.is_empty() {
        // The route has not been admitted (or observed) yet: the API server accepted the object but
        // no gateway has written a status for it. Not `Missing` (it exists), not `Healthy` (nothing
        // is serving yet).
        return ResourceHealth::progressing(
            "HTTPRoute has not reported a status.parents entry yet",
        );
    }

    let mut worst: Option<ResourceHealth> = None;
    for (index, parent) in parents.iter().enumerate() {
        let verdict = parent_health(object.metadata.generation, index, parent);
        worst = match worst {
            // Deterministic worst-wins: the first parent carrying the highest precedence decides,
            // so two passes over the same object produce the same message.
            Some(current) if precedence(current.status) >= precedence(verdict.status) => {
                Some(current)
            }
            _ => Some(verdict),
        };
        if worst
            .as_ref()
            .is_some_and(|health| health.status == super::HealthStatus::Degraded)
        {
            // A rejected parent is the worst possible verdict, so there is nothing left to learn.
            break;
        }
    }

    match worst {
        Some(worst) => worst,
        // Unreachable (`parents` is non-empty), and deliberately not a panic.
        None => ResourceHealth::progressing("HTTPRoute has no parent status yet"),
    }
}

/// Verdict for one `status.parents[i]` entry.
fn parent_health(generation: Option<i64>, index: usize, parent: &Value) -> ResourceHealth {
    let conditions = values::condition_views(values::array(parent, "conditions"));
    if conditions.is_empty() {
        return ResourceHealth::progressing(format!(
            "gateway parent {index} has not reported any conditions yet"
        ));
    }

    for condition in &conditions {
        if is_stale(generation, condition.observed_generation) {
            return ResourceHealth::progressing(format!(
                "gateway parent {index} {} condition has not observed the latest generation yet",
                condition.type_
            ));
        }
    }

    let mut progressing: Option<ResourceHealth> = None;
    for type_ in ROUTE_PARENT_CONDITIONS {
        let Some(condition) = values::condition(&conditions, type_) else {
            // Not settled: a parent that has not published one of the two conditions yet cannot be
            // said to have accepted the route.
            progressing.get_or_insert_with(|| {
                ResourceHealth::progressing(format!(
                    "gateway parent {index} has not reported a {type_} condition yet"
                ))
            });
            continue;
        };
        if condition.is_true() {
            continue;
        }
        if condition.is_false() {
            return ResourceHealth::degraded(format!(
                "gateway parent {index} reports {type_}=False ({})",
                condition.describe()
            ));
        }
        progressing.get_or_insert_with(|| {
            ResourceHealth::progressing(format!(
                "gateway parent {index} reports {type_}={}",
                if condition.status.is_empty() {
                    "unset"
                } else {
                    condition.status
                }
            ))
        });
    }

    match progressing {
        Some(progressing) => progressing,
        None => ResourceHealth::healthy(format!(
            "all {} conditions are True",
            ROUTE_PARENT_CONDITIONS.join("/")
        )),
    }
}

/// Argo Rollouts `Rollout` health from `status.phase` (`T20.3`).
///
/// `Paused` is [`super::HealthStatus::Suspended`], not `Degraded`: an operator (or a
/// `spec.strategy.canary.pause`) paused the rollout on purpose, and failing the wave would abort a
/// perfectly healthy canary.
#[must_use]
pub fn argo_rollout(object: &DynamicObject) -> ResourceHealth {
    if status_is_stale(object) {
        return ResourceHealth::progressing(MSG_WAITING_FOR_OBSERVATION);
    }

    let conditions = values::conditions(object);
    if let Some(invalid) = values::condition(&conditions, "InvalidSpec")
        && invalid.is_true()
    {
        // Argo publishes `InvalidSpec=True` for a spec its own controller refuses. The rollout will
        // never become `Healthy` without a new spec, so waiting is pointless.
        return ResourceHealth::degraded(format!(
            "Rollout has an invalid spec ({})",
            invalid.describe()
        ));
    }

    let phase = values::text(object, &["status", "phase"]).unwrap_or_default();
    match phase {
        "Healthy" => ResourceHealth::healthy("Rollout is Healthy"),
        "Progressing" => ResourceHealth::progressing("Rollout is Progressing"),
        "Paused" => ResourceHealth::suspended("Rollout is Paused"),
        "Degraded" => ResourceHealth::degraded(format!(
            "Rollout is Degraded{}",
            detail(values::text(object, &["status", "message"]))
        )),
        "" => ResourceHealth::progressing("Rollout has not reported a status.phase yet"),
        other => ResourceHealth::unknown(format!(
            "Rollout reports an unrecognized status.phase {other:?}"
        )),
    }
}

/// Flagger `Canary` health from `status.phase` (`T20.3`).
///
/// Flagger never writes `Suspended`: a canary that is waiting for its bake is converging, because
/// the rollout is live and only the traffic weight is being held.
#[must_use]
pub fn flagger_canary(object: &DynamicObject) -> ResourceHealth {
    if status_is_stale(object) {
        return ResourceHealth::progressing(MSG_WAITING_FOR_OBSERVATION);
    }

    let phase = values::text(object, &["status", "phase"]).unwrap_or_default();
    if phase.is_empty() {
        return ResourceHealth::progressing("Canary has not reported a status.phase yet");
    }
    if CANARY_HEALTHY_PHASES.contains(&phase) {
        return ResourceHealth::healthy(format!("Canary is {phase}"));
    }
    if CANARY_PROGRESSING_PHASES.contains(&phase) {
        return ResourceHealth::progressing(format!("Canary is {phase}"));
    }
    if CANARY_DEGRADED_PHASES.contains(&phase) {
        // Flagger writes the failing check count into `status.failedChecks`; the count is a number,
        // so it is safe to surface verbatim (and it is what an operator acts on).
        let failed_checks = values::count(object, &["status", "failedChecks"]);
        let suffix = match failed_checks {
            0 => String::new(),
            1 => " after 1 failed check".to_owned(),
            count => format!(" after {count} failed checks"),
        };
        return ResourceHealth::degraded(format!(
            "Canary is Failed{suffix}{}",
            detail(values::text(object, &["status", "message"]))
        ));
    }
    ResourceHealth::unknown(format!(
        "Canary reports an unrecognized status.phase {phase:?}"
    ))
}

/// Appends `text` as a parenthesized detail when it is non-empty.
fn detail(text: Option<&str>) -> String {
    match text.map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => format!(" ({text})"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::status::HealthStatus;
    use kube::api::DynamicObject;
    use serde_json::json;

    use super::*;
    use crate::health::{HealthConfig, HealthRegistry, ResourceKey};

    fn object(value: serde_json::Value) -> DynamicObject {
        serde_json::from_value(value).expect("valid DynamicObject")
    }

    fn route(parents: serde_json::Value, generation: i64) -> DynamicObject {
        object(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "api", "namespace": "payments", "generation": generation },
            "status": { "parents": parents },
        }))
    }

    fn accepted(observed: i64) -> serde_json::Value {
        json!({
            "parentRef": { "name": "public" },
            "controllerName": "example.com/gateway",
            "conditions": [
                { "type": "Accepted", "status": "True", "reason": "Accepted",
                  "message": "route is accepted", "observedGeneration": observed },
                { "type": "ResolvedRefs", "status": "True", "reason": "ResolvedRefs",
                  "observedGeneration": observed },
            ],
        })
    }

    /// Every `HTTPRoute` transition the roadmap lists, plus the stale-generation guard.
    #[test]
    fn http_route_transitions_are_pinned() {
        // No parent status at all: the route exists but no gateway has admitted it.
        let no_parents = route(json!([]), 1);
        assert_eq!(
            http_route(&no_parents).status,
            HealthStatus::Progressing,
            "a route without parent status is converging, never Unknown/Healthy"
        );

        // Both conditions True -> Healthy.
        let healthy = route(json!([accepted(3)]), 3);
        let health = http_route(&healthy);
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(
            health.message.contains("Accepted/ResolvedRefs"),
            "{}",
            health.message
        );

        // Accepted=False -> Degraded, with the gateway's own reason surfaced.
        let rejected = route(
            json!([{
                "parentRef": { "name": "public" },
                "conditions": [
                    { "type": "Accepted", "status": "False", "reason": "NotAllowedByListeners",
                      "message": "no listener permits this route", "observedGeneration": 3 },
                    { "type": "ResolvedRefs", "status": "True", "observedGeneration": 3 },
                ],
            }]),
            3,
        );
        let health = http_route(&rejected);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("NotAllowedByListeners"),
            "{}",
            health.message
        );
        assert!(
            health.message.contains("no listener permits"),
            "{}",
            health.message
        );

        // ResolvedRefs=False is Degraded even when Accepted=True: the route points at nothing.
        let unresolved = route(
            json!([{
                "conditions": [
                    { "type": "Accepted", "status": "True", "observedGeneration": 3 },
                    { "type": "ResolvedRefs", "status": "False", "reason": "InvalidKind",
                      "observedGeneration": 3 },
                ],
            }]),
            3,
        );
        assert_eq!(http_route(&unresolved).status, HealthStatus::Degraded);

        // A missing / `Unknown` condition is converging.
        let half_reported = route(
            json!([{ "conditions": [
                { "type": "Accepted", "status": "True", "observedGeneration": 3 },
            ] }]),
            3,
        );
        assert_eq!(http_route(&half_reported).status, HealthStatus::Progressing);

        let undecided = route(
            json!([{ "conditions": [
                { "type": "Accepted", "status": "Unknown", "observedGeneration": 3 },
                { "type": "ResolvedRefs", "status": "True", "observedGeneration": 3 },
            ] }]),
            3,
        );
        assert_eq!(http_route(&undecided).status, HealthStatus::Progressing);

        let no_conditions = route(json!([{ "parentRef": { "name": "public" } }]), 3);
        assert_eq!(http_route(&no_conditions).status, HealthStatus::Progressing);
    }

    /// The trap guard: a stale `observedGeneration` beats a `True` condition.
    #[test]
    fn http_route_stale_observed_generation_is_progressing_not_healthy() {
        // Condition-level staleness (the Gateway API form): generation 4, conditions on 3.
        let stale_condition = route(json!([accepted(3)]), 4);
        let health = http_route(&stale_condition);
        assert_eq!(health.status, HealthStatus::Progressing);
        assert!(
            health.message.contains("observed the latest generation"),
            "{}",
            health.message
        );

        // Status-level staleness (a newer Gateway API revision publishes it): beats a True parent.
        let stale_status = object(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "api", "generation": 9 },
            "status": { "observedGeneration": 8, "parents": [accepted(9)] },
        }));
        let health = http_route(&stale_status);
        assert_eq!(health.status, HealthStatus::Progressing);
        assert_eq!(health.message, MSG_WAITING_FOR_OBSERVATION);

        // An absent generation (or an absent observedGeneration) is never stale.
        let unversioned = object(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "api" },
            "status": { "parents": [{
                "conditions": [
                    { "type": "Accepted", "status": "True" },
                    { "type": "ResolvedRefs", "status": "True" },
                ],
            }] },
        }));
        assert_eq!(http_route(&unversioned).status, HealthStatus::Healthy);
    }

    /// Two gateways, one accepting and one rejecting: the worst parent decides.
    #[test]
    fn http_route_aggregates_every_parent_worst_first() {
        let mixed = route(
            json!([
                accepted(2),
                { "conditions": [
                    { "type": "Accepted", "status": "False", "reason": "NotAllowedByListeners",
                      "observedGeneration": 2 },
                    { "type": "ResolvedRefs", "status": "True", "observedGeneration": 2 },
                ] },
            ]),
            2,
        );
        let health = http_route(&mixed);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(health.message.contains("parent 1"), "{}", health.message);

        // Reversing the order does not change the verdict: it is aggregated, not "first wins".
        let reversed = route(
            json!([
                { "conditions": [
                    { "type": "Accepted", "status": "False", "reason": "NotAllowedByListeners",
                      "observedGeneration": 2 },
                    { "type": "ResolvedRefs", "status": "True", "observedGeneration": 2 },
                ] },
                accepted(2),
            ]),
            2,
        );
        assert_eq!(http_route(&reversed).status, HealthStatus::Degraded);
    }

    fn rollout(phase: &str, generation: i64, observed: i64) -> DynamicObject {
        object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api", "namespace": "payments", "generation": generation },
            "status": { "phase": phase, "observedGeneration": observed },
        }))
    }

    #[test]
    fn rollout_phases_are_pinned() {
        for (phase, expected) in [
            ("Healthy", HealthStatus::Healthy),
            ("Progressing", HealthStatus::Progressing),
            ("Paused", HealthStatus::Suspended),
            ("Degraded", HealthStatus::Degraded),
        ] {
            let live = rollout(phase, 3, 3);
            let health = argo_rollout(&live);
            assert_eq!(health.status, expected, "phase {phase}: {}", health.message);
            assert!(health.message.contains(phase), "{}", health.message);
        }
        // Every documented phase is covered above.
        assert_eq!(ROLLOUT_PHASES.len(), 4);

        // No phase yet: the rollout was just created.
        let fresh = object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api" },
            "status": {},
        }));
        assert_eq!(argo_rollout(&fresh).status, HealthStatus::Progressing);

        // An unrecognized phase is reported honestly instead of guessed.
        let future = rollout("Reconciling", 1, 1);
        let health = argo_rollout(&future);
        assert_eq!(health.status, HealthStatus::Unknown);
        assert!(health.message.contains("Reconciling"), "{}", health.message);
    }

    #[test]
    fn rollout_stale_generation_and_invalid_spec_guard_the_healthy_phase() {
        let stale = rollout("Healthy", 7, 6);
        let health = argo_rollout(&stale);
        assert_eq!(health.status, HealthStatus::Progressing);
        assert_eq!(health.message, MSG_WAITING_FOR_OBSERVATION);

        // A stale `Degraded` is still converging: the controller has not judged the new spec yet.
        let stale_degraded = rollout("Degraded", 7, 6);
        assert_eq!(
            argo_rollout(&stale_degraded).status,
            HealthStatus::Progressing
        );

        let invalid_spec = object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api", "generation": 2 },
            "status": {
                "phase": "Progressing",
                "observedGeneration": 2,
                "conditions": [{ "type": "InvalidSpec", "status": "True",
                                 "reason": "InvalidSpec", "message": "unknown field spec.foo" }],
            },
        }));
        let health = argo_rollout(&invalid_spec);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("unknown field"),
            "{}",
            health.message
        );

        // A `Degraded` rollout surfaces its own message.
        let degraded = object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api", "generation": 1 },
            "status": { "phase": "Degraded", "observedGeneration": 1,
                        "message": "RolloutAborted: InjectedFailure" },
        }));
        let health = argo_rollout(&degraded);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("InjectedFailure"),
            "{}",
            health.message
        );
    }

    fn canary(phase: &str, observed: Option<i64>) -> DynamicObject {
        let mut status = json!({ "phase": phase });
        if let Some(observed) = observed {
            status["observedGeneration"] = json!(observed);
        }
        object(json!({
            "apiVersion": "flagger.app/v1beta1",
            "kind": "Canary",
            "metadata": { "name": "api", "namespace": "payments", "generation": 3 },
            "status": status,
        }))
    }

    #[test]
    fn flagger_canary_phases_are_pinned() {
        for phase in CANARY_HEALTHY_PHASES {
            assert_eq!(
                flagger_canary(&canary(phase, Some(3))).status,
                HealthStatus::Healthy,
                "{phase}"
            );
        }
        for phase in CANARY_PROGRESSING_PHASES {
            assert_eq!(
                flagger_canary(&canary(phase, Some(3))).status,
                HealthStatus::Progressing,
                "{phase}"
            );
        }
        for phase in CANARY_DEGRADED_PHASES {
            assert_eq!(
                flagger_canary(&canary(phase, Some(3))).status,
                HealthStatus::Degraded,
                "{phase}"
            );
        }

        // The three groups are disjoint and exhaustive over the documented spellings.
        let mut seen = std::collections::BTreeSet::new();
        for phase in CANARY_HEALTHY_PHASES
            .iter()
            .chain(CANARY_PROGRESSING_PHASES.iter())
            .chain(CANARY_DEGRADED_PHASES.iter())
        {
            assert!(seen.insert(*phase), "{phase} is mapped twice");
        }

        // A canary with no phase yet is converging.
        assert_eq!(
            flagger_canary(&canary("", Some(3))).status,
            HealthStatus::Progressing
        );
        // An unknown phase is reported, never guessed.
        assert_eq!(
            flagger_canary(&canary("Hibernating", Some(3))).status,
            HealthStatus::Unknown
        );
    }

    /// `T20.3` finding H2: the phase strings are Flagger's own **wire** spellings, spelled out as
    /// literals here (never through the constants under test) so a typo in the constant list cannot
    /// keep the test green. `Finalizing` is American; the list used to carry the British
    /// `Finalising`, which matches no canary Flagger ever writes — every finished canary therefore
    /// reported `Unknown` and burned the wave timeout.
    #[test]
    fn flagger_canary_maps_the_literal_production_phase_strings() {
        for phase in ["Initialized", "Succeeded", "Finalized"] {
            let health = flagger_canary(&canary(phase, Some(3)));
            assert_eq!(health.status, HealthStatus::Healthy, "{phase}: {health:?}");
            assert!(health.message.contains(phase), "{}", health.message);
        }
        for phase in [
            "Initializing",
            "Waiting",
            "Progressing",
            "Promoting",
            "Finalizing",
            "Terminating",
        ] {
            let health = flagger_canary(&canary(phase, Some(3)));
            assert_eq!(
                health.status,
                HealthStatus::Progressing,
                "{phase} is a real Flagger phase and must not fall through to Unknown: {health:?}"
            );
            assert!(health.message.contains(phase), "{}", health.message);
        }
        let health = flagger_canary(&canary("Failed", Some(3)));
        assert_eq!(health.status, HealthStatus::Degraded, "{health:?}");

        // The misspelling is gone: it never appears on the wire, so nothing may claim it.
        assert!(
            !CANARY_PROGRESSING_PHASES.contains(&"Finalising"),
            "`Finalising` is not a Flagger phase: {:?}",
            CANARY_PROGRESSING_PHASES
        );
        assert!(CANARY_PROGRESSING_PHASES.contains(&"Finalizing"));
        assert!(CANARY_PROGRESSING_PHASES.contains(&"Terminating"));
    }

    /// `T20.3` finding H3: the stale-generation guard must read the generation Argo Rollouts
    /// actually publishes — a **string** — for both the object-level and the condition-level field.
    #[test]
    fn a_string_observed_generation_still_guards_staleness() {
        // Object level: a `Rollout` on generation 4 that has observed 3 is still converging, so its
        // (stale) `Healthy` must never promote the next wave.
        let stale = object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api", "namespace": "payments", "generation": 4 },
            "status": { "phase": "Healthy", "observedGeneration": "3" },
        }));
        let health = argo_rollout(&stale);
        assert_eq!(health.status, HealthStatus::Progressing, "{health:?}");
        assert_eq!(health.message, MSG_WAITING_FOR_OBSERVATION);

        // The same object one generation later is genuinely settled.
        let settled = object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api", "namespace": "payments", "generation": 4 },
            "status": { "phase": "Healthy", "observedGeneration": "4" },
        }));
        assert_eq!(argo_rollout(&settled).status, HealthStatus::Healthy);

        // Condition level: the Gateway API form of the same field.
        let route = object(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "api", "namespace": "payments", "generation": 4 },
            "status": { "parents": [{
                "conditions": [
                    { "type": "Accepted", "status": "True", "observedGeneration": "3" },
                    { "type": "ResolvedRefs", "status": "True", "observedGeneration": "3" },
                ],
            }] },
        }));
        let health = http_route(&route);
        assert_eq!(health.status, HealthStatus::Progressing, "{health:?}");
        assert!(
            health.message.contains("observed the latest generation"),
            "{}",
            health.message
        );

        // And a Flagger canary that publishes the string form is guarded the same way.
        let stale_canary = object(json!({
            "apiVersion": "flagger.app/v1beta1",
            "kind": "Canary",
            "metadata": { "name": "api", "namespace": "payments", "generation": 4 },
            "status": { "phase": "Initialized", "observedGeneration": "3" },
        }));
        assert_eq!(
            flagger_canary(&stale_canary).status,
            HealthStatus::Progressing
        );

        // A generation that is not a number at all is "unknown", which is documented as not stale:
        // guessing here would fail a healthy rollout on a typo.
        let unreadable = object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api", "namespace": "payments", "generation": 4 },
            "status": { "phase": "Healthy", "observedGeneration": "four" },
        }));
        assert_eq!(argo_rollout(&unreadable).status, HealthStatus::Healthy);
    }

    #[test]
    fn flagger_canary_stale_generation_and_failure_detail_are_guard_rails() {
        // A stale `Initialized` must not promote the next wave.
        let stale = canary("Initialized", Some(2));
        let health = flagger_canary(&stale);
        assert_eq!(health.status, HealthStatus::Progressing);
        assert_eq!(health.message, MSG_WAITING_FOR_OBSERVATION);

        // Flagger does not write `status.observedGeneration` in every version: absent is not stale.
        let no_generation = canary("Initialized", None);
        assert_eq!(flagger_canary(&no_generation).status, HealthStatus::Healthy);

        let failed = object(json!({
            "apiVersion": "flagger.app/v1beta1",
            "kind": "Canary",
            "metadata": { "name": "api", "generation": 1 },
            "status": { "phase": "Failed", "observedGeneration": 1, "failedChecks": 3,
                        "message": "HTTP request failed" },
        }));
        let health = flagger_canary(&failed);
        assert_eq!(health.status, HealthStatus::Degraded);
        assert!(
            health.message.contains("3 failed checks"),
            "{}",
            health.message
        );
        assert!(
            health.message.contains("HTTP request failed"),
            "{}",
            health.message
        );
    }

    /// The three evaluators are registered under `(group, kind)`, never under an API version.
    #[test]
    fn the_builtin_registry_handles_the_three_progressive_kinds() {
        let registry = HealthRegistry::builtin();
        for (group, kind) in [
            (GATEWAY_GROUP, "HTTPRoute"),
            (ARGO_ROLLOUT_GROUP, "Rollout"),
            (FLAGGER_GROUP, "Canary"),
        ] {
            assert!(
                registry.handles(group, kind),
                "{group}/{kind} must be built in"
            );
        }

        // Dispatching through the registry (the controller's path) resolves the same verdict, and a
        // version bump cannot change it because the registry key is `(group, kind)` only.
        let config = HealthConfig::default();
        for version in ["v1", "v1beta1", "v1alpha1"] {
            let key = ResourceKey::new(
                GATEWAY_GROUP,
                "HTTPRoute",
                Some("payments".to_owned()),
                "api",
            );
            let live = route(json!([accepted(1)]), 1);
            assert_eq!(
                registry.evaluate(&key, &live, &config).status,
                HealthStatus::Healthy,
                "{version}"
            );
        }

        // A generic CR of the same kind name in another group still falls back to the heuristic.
        assert!(!registry.handles("example.com", "Rollout"));
    }

    /// `T20.3` nit: version independence is only *proven* if the objects actually differ by
    /// `apiVersion`. Every progressive kind is dispatched on `(group, kind)`, so the same status read
    /// through `v1beta1` and through `v1` must produce the identical verdict — an API-server version
    /// promotion mid-canary can never silently fall back to the generic `Ready` heuristic.
    #[test]
    fn the_verdict_is_version_independent_for_every_progressive_kind() {
        let registry = HealthRegistry::builtin();
        let config = HealthConfig::default();

        // `(group, kind, fixture builder, expected verdict)`.
        type Case = (
            &'static str,
            &'static str,
            fn(&str) -> serde_json::Value,
            HealthStatus,
        );
        let cases: [Case; 3] = [
            (
                GATEWAY_GROUP,
                "HTTPRoute",
                |api_version| {
                    json!({
                        "apiVersion": api_version,
                        "kind": "HTTPRoute",
                        "metadata": { "name": "api", "namespace": "payments", "generation": 2 },
                        "status": { "parents": [{
                            "conditions": [
                                { "type": "Accepted", "status": "True", "observedGeneration": 2 },
                                { "type": "ResolvedRefs", "status": "True",
                                  "observedGeneration": 2 },
                            ],
                        }] },
                    })
                },
                HealthStatus::Healthy,
            ),
            (
                ARGO_ROLLOUT_GROUP,
                "Rollout",
                |api_version| {
                    json!({
                        "apiVersion": api_version,
                        "kind": "Rollout",
                        "metadata": { "name": "api", "namespace": "payments", "generation": 2 },
                        "status": { "phase": "Paused", "observedGeneration": "2" },
                    })
                },
                HealthStatus::Suspended,
            ),
            (
                FLAGGER_GROUP,
                "Canary",
                |api_version| {
                    json!({
                        "apiVersion": api_version,
                        "kind": "Canary",
                        "metadata": { "name": "api", "namespace": "payments", "generation": 2 },
                        "status": { "phase": "Finalizing", "observedGeneration": "2" },
                    })
                },
                HealthStatus::Progressing,
            ),
        ];

        for (group, kind, build, expected) in cases {
            let key = ResourceKey::new(group, kind, Some("payments".to_owned()), "api");
            let mut versions = Vec::new();
            for version in ["v1", "v1beta1", "v1alpha1"] {
                let api_version = format!("{group}/{version}");
                // The objects really are different documents on the wire...
                versions.push(api_version.clone());
                let live = object(build(&api_version));
                assert_eq!(
                    live.types.as_ref().map(|types| types.api_version.as_str()),
                    Some(api_version.as_str()),
                    "the fixture must carry the version under test"
                );
                assert_eq!(
                    registry.evaluate(&key, &live, &config).status,
                    expected,
                    "{group}/{kind} through {api_version}"
                );
            }
            assert_eq!(versions.len(), 3, "every version was exercised");
            // ...and the key the dispatch uses has no version in it at all.
            assert!(!key.to_string().contains("v1"), "{}", key);
        }

        // A version bump alone is not a key change: the inventory/orphan maths rest on this.
        let v1 = ResourceKey::new(GATEWAY_GROUP, "HTTPRoute", None, "api");
        let v1beta1 = ResourceKey::new(GATEWAY_GROUP, "HTTPRoute", None, "api");
        assert_eq!(v1, v1beta1);
    }

    /// A malformed status (wrong types, missing fields) degrades the verdict, never panics.
    #[test]
    fn malformed_statuses_are_total() {
        let hostile = object(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "api", "generation": 2 },
            "status": { "observedGeneration": "two", "parents": "not-an-array" },
        }));
        let health = http_route(&hostile);
        assert_eq!(health.status, HealthStatus::Progressing);

        let nested = object(json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "HTTPRoute",
            "metadata": { "name": "api", "generation": 2 },
            "status": { "parents": [ { "conditions": "nope" }, { "conditions": [ { "status": "True" } ] } ] },
        }));
        assert_eq!(http_route(&nested).status, HealthStatus::Progressing);

        let no_status = object(json!({
            "apiVersion": "argoproj.io/v1alpha1",
            "kind": "Rollout",
            "metadata": { "name": "api", "generation": 1 },
        }));
        assert_eq!(argo_rollout(&no_status).status, HealthStatus::Progressing);
        assert_eq!(flagger_canary(&no_status).status, HealthStatus::Progressing);
    }
}
