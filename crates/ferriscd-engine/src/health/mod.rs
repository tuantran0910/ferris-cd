//! Phase 09 health assessment engine: the `HealthStatus` lattice, the `HealthEvaluator` trait
//! with its `(group, kind)` registry, and the application-level aggregation used by
//! `Application.status.health`.
//!
//! # Why a separate engine
//!
//! Sync status and health status answer different questions (`T09.5` trap guard: they must never
//! be conflated):
//!
//! | Question | Field | Owner |
//! |---|---|---|
//! | does live state match Git? | `status.sync.status` | [`crate::diff`] |
//! | are the workloads actually serving? | `status.health.status` | this module |
//!
//! A `Deployment` can be perfectly `Synced` (its `spec` is exactly what Git says) while every pod
//! is `ImagePullBackOff`. The reverse is also possible: a HPA-scaled Deployment is `OutOfSync`
//! and completely healthy. Health is therefore computed from the **live object's `status`**, never
//! from the diff.
//!
//! # The lattice
//!
//! [`HealthStatus`] is re-exported from `ferriscd_crd::status` (there is exactly one wire type, so
//! no conversion layer can drift from the CRD schema). Aggregation is strict, worst-wins:
//!
//! ```text
//! Degraded > Missing > Progressing > Suspended > Unknown > Healthy
//! ```
//!
//! `Missing` outranks `Progressing` because "the object does not exist" is a stronger statement
//! than "the object is converging"; `Suspended` outranks `Unknown` because an intentionally paused
//! workload is *known* to be idle, while `Unknown` means we could not read the status at all. An
//! empty resource set is `Healthy` (an `Application` that manages nothing has nothing broken).
//!
//! # Purity
//!
//! Everything in this module is pure and I/O-free: it takes the live objects the controller
//! already fetched (one scoped read per reconcile, model 1 drift detection) and returns a verdict.
//! No evaluator issues an API call, reads the clock, or logs. That makes every edge case
//! (paused Deployments, zero replicas, `OnDelete` StatefulSets, `Job` retries, stale
//! `observedGeneration`) provable in a hermetic snapshot test.

pub mod crd;
pub mod runtime;
pub(crate) mod values;
pub mod workloads;

use std::collections::BTreeMap;
use std::fmt;

use kube::api::DynamicObject;

use crate::manifest::ResourceKey;

pub use crd::{CONDITION_PRIORITY, TRANSIENT_REASONS, generic_crd_health};
pub use ferriscd_crd::status::{HealthStatus, MAX_STATUS_MESSAGE_CHARS};
pub use runtime::{LOAD_BALANCER_HEALTH_ANNOTATION, LoadBalancerPolicy};

/// Message every workload evaluator reports while `status.observedGeneration` lags
/// `metadata.generation` (`T09.2`).
///
/// This check is mandatory and must come first: a `Deployment` whose `spec` just changed still
/// carries the *previous* rollout's counters, so `updatedReplicas == availableReplicas == desired`
/// is true for a pass or two after an edit. Reporting `Healthy` there is the classic false-green
/// — the new pods have not even been created yet.
pub const MSG_WAITING_FOR_OBSERVATION: &str = "Waiting for controller to observe generation";

/// Health verdict for a single resource.
///
/// `message` is operator-facing and therefore **bounded and secret-free**: callers persist it into
/// `Application.status.resources[].message`, which is truncated to
/// [`MAX_STATUS_MESSAGE_CHARS`]. No evaluator ever reads `Secret.data`, so no message can carry a
/// secret value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceHealth {
    /// The verdict.
    pub status: HealthStatus,
    /// Short human-readable explanation.
    pub message: String,
}

impl ResourceHealth {
    /// Builds a verdict.
    #[must_use]
    pub fn new(status: HealthStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    /// `Healthy`.
    #[must_use]
    pub fn healthy(message: impl Into<String>) -> Self {
        Self::new(HealthStatus::Healthy, message)
    }

    /// `Progressing`.
    #[must_use]
    pub fn progressing(message: impl Into<String>) -> Self {
        Self::new(HealthStatus::Progressing, message)
    }

    /// `Degraded`.
    #[must_use]
    pub fn degraded(message: impl Into<String>) -> Self {
        Self::new(HealthStatus::Degraded, message)
    }

    /// `Suspended`.
    #[must_use]
    pub fn suspended(message: impl Into<String>) -> Self {
        Self::new(HealthStatus::Suspended, message)
    }

    /// `Missing`.
    #[must_use]
    pub fn missing(message: impl Into<String>) -> Self {
        Self::new(HealthStatus::Missing, message)
    }

    /// `Unknown`.
    #[must_use]
    pub fn unknown(message: impl Into<String>) -> Self {
        Self::new(HealthStatus::Unknown, message)
    }

    /// Returns whether the verdict is [`HealthStatus::Healthy`].
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }
}

/// Aggregation precedence rank: strictly higher wins.
///
/// `Degraded > Missing > Progressing > Suspended > Unknown > Healthy`, the order `T09.1` specifies
/// and [`PRECEDENCE_ORDER`] spells out. `MASTER_PLAN` FR-08 and the roadmap use the same order, so
/// there is one contract and every lattice test pins it.
#[must_use]
pub const fn precedence(status: HealthStatus) -> u8 {
    match status {
        HealthStatus::Degraded => 5,
        HealthStatus::Missing => 4,
        HealthStatus::Progressing => 3,
        HealthStatus::Suspended => 2,
        HealthStatus::Unknown => 1,
        HealthStatus::Healthy => 0,
    }
}

/// Stable label used in health messages (`Healthy`, `Progressing`, …).
#[must_use]
pub const fn status_label(status: HealthStatus) -> &'static str {
    match status {
        HealthStatus::Healthy => "Healthy",
        HealthStatus::Progressing => "Progressing",
        HealthStatus::Degraded => "Degraded",
        HealthStatus::Suspended => "Suspended",
        HealthStatus::Missing => "Missing",
        HealthStatus::Unknown => "Unknown",
    }
}

/// Strict worst-wins aggregation; an empty iterator is [`HealthStatus::Healthy`].
#[must_use]
pub fn aggregate(statuses: impl IntoIterator<Item = HealthStatus>) -> HealthStatus {
    let mut worst = HealthStatus::Healthy;
    for status in statuses {
        if precedence(status) > precedence(worst) {
            worst = status;
        }
    }
    worst
}

/// The lattice in precedence order, worst first (`Degraded > Missing > Progressing > Suspended >
/// Unknown > Healthy`), so the documented order and [`precedence`] can never drift apart.
pub const PRECEDENCE_ORDER: [HealthStatus; 6] = [
    HealthStatus::Degraded,
    HealthStatus::Missing,
    HealthStatus::Progressing,
    HealthStatus::Suspended,
    HealthStatus::Unknown,
    HealthStatus::Healthy,
];

/// Tunables that make the built-in evaluators usable on clusters that cannot satisfy a default.
///
/// The two knobs exist because a local cluster legitimately fails two of the "healthy" tests:
/// `kind` has no cloud load-balancer controller (a `Service: LoadBalancer` never receives an
/// ingress address) and a spec-only CRD never writes `status.conditions`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthConfig {
    /// How a `Service` of type `LoadBalancer` is judged.
    pub load_balancer: LoadBalancerPolicy,
    /// How a custom resource **with no `status.conditions` at all** is judged.
    pub cr_without_conditions: NoConditionPolicy,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            // Production default: a `LoadBalancer` Service is not serving until it has an address.
            load_balancer: LoadBalancerPolicy::RequireIngress,
            // A CR with no conditions reports no state, which for a spec-only CRD is normal.
            cr_without_conditions: NoConditionPolicy::Healthy,
        }
    }
}

/// What to do with an unrecognized custom resource whose `status.conditions` is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoConditionPolicy {
    /// Treat it as healthy (the default; correct for spec-only CRDs).
    Healthy,
    /// Report [`HealthStatus::Unknown`] (correct when every CR of that group is expected to
    /// publish conditions, and silence should be visible).
    Unknown,
}

/// Per-kind health evaluator.
///
/// Implementations **must** be pure: no API calls, no clock, no logging. The only input is the
/// live object and the config.
pub trait HealthEvaluator: Send + Sync {
    /// Evaluates one live object.
    fn evaluate(&self, object: &DynamicObject, config: &HealthConfig) -> ResourceHealth;
}

/// Dispatch key: the version-agnostic `(group, kind)` pair, matching [`ResourceKey`] identity
/// (ADR-003: an API `version` upgrade must never change how a resource is evaluated).
pub type KindKey = (String, String);

/// Registry of [`HealthEvaluator`]s keyed by `(group, kind)`.
///
/// Unknown kinds fall back to the generic condition heuristic ([`generic_crd_health`]), never to
/// `Unknown`: a third-party CR that publishes a `Ready` condition is judged correctly without a
/// line of per-CRD code.
pub struct HealthRegistry {
    evaluators: BTreeMap<KindKey, Box<dyn HealthEvaluator>>,
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::builtin()
    }
}

impl fmt::Debug for HealthRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthRegistry")
            .field(
                "kinds",
                &self
                    .evaluators
                    .keys()
                    .map(|(group, kind)| format!("{group}/{kind}"))
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl HealthRegistry {
    /// An empty registry (every kind falls through to the generic heuristic).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            evaluators: BTreeMap::new(),
        }
    }

    /// The production registry: passive built-ins (`T09.1`), core workloads (`T09.2`), runtime
    /// resources (`T09.3`), and the generic CR heuristic (`T09.4`).
    #[must_use]
    pub fn builtin() -> Self {
        let mut registry = Self::empty();
        registry.register_builtins();
        registry
    }

    /// Registers every built-in evaluator (idempotent: a later registration replaces an earlier
    /// one for the same kind).
    fn register_builtins(&mut self) {
        use workloads::{DaemonSetHealth, DeploymentHealth, ReplicaSetHealth, StatefulSetHealth};

        // --- T09.1: passive resources are Healthy whenever they exist ---------------------
        for (group, kind) in [
            ("", "ConfigMap"),
            ("", "Secret"),
            ("", "ServiceAccount"),
            ("", "Namespace"),
            ("rbac.authorization.k8s.io", "Role"),
            ("rbac.authorization.k8s.io", "ClusterRole"),
            ("rbac.authorization.k8s.io", "RoleBinding"),
            ("rbac.authorization.k8s.io", "ClusterRoleBinding"),
        ] {
            self.insert(group, kind, PassiveHealth::new(kind));
        }
        self.insert(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            CustomResourceDefinitionHealth,
        );

        // --- T09.2: core workloads --------------------------------------------------------
        self.insert("apps", "Deployment", DeploymentHealth);
        self.insert("apps", "StatefulSet", StatefulSetHealth);
        self.insert("apps", "DaemonSet", DaemonSetHealth);
        self.insert("apps", "ReplicaSet", ReplicaSetHealth);

        // --- T09.3: runtime resources -----------------------------------------------------
        self.insert("", "Pod", runtime::PodHealth);
        self.insert("batch", "Job", runtime::JobHealth);
        self.insert("", "Service", runtime::ServiceHealth);
        self.insert("networking.k8s.io", "Ingress", runtime::IngressHealth);
        self.insert(
            "",
            "PersistentVolumeClaim",
            runtime::PersistentVolumeClaimHealth,
        );
    }

    /// Registers (or replaces) the evaluator of `group`/`kind`.
    pub fn insert(
        &mut self,
        group: impl Into<String>,
        kind: impl Into<String>,
        evaluator: impl HealthEvaluator + 'static,
    ) {
        self.evaluators
            .insert((group.into(), kind.into()), Box::new(evaluator));
    }

    /// Returns the evaluator registered for `group`/`kind`, if any.
    #[must_use]
    pub fn lookup(&self, group: &str, kind: &str) -> Option<&dyn HealthEvaluator> {
        self.evaluators
            .get(&(group.to_owned(), kind.to_owned()))
            .map(Box::as_ref)
    }

    /// Returns whether a built-in (or explicitly registered) evaluator handles `group`/`kind`.
    #[must_use]
    pub fn handles(&self, group: &str, kind: &str) -> bool {
        self.lookup(group, kind).is_some()
    }

    /// Evaluates one live object, falling back to the generic CR heuristic.
    #[must_use]
    pub fn evaluate(
        &self,
        key: &ResourceKey,
        object: &DynamicObject,
        config: &HealthConfig,
    ) -> ResourceHealth {
        match self.lookup(&key.group, &key.kind) {
            Some(evaluator) => evaluator.evaluate(object, config),
            None => generic_crd_health(object, config),
        }
    }
}

/// `Healthy` for any resource that has no rollout state worth watching (`T09.1` trap guard).
///
/// A `ConfigMap`, `Secret`, `ServiceAccount`, `Namespace` or RBAC object is either present (and
/// therefore serving its purpose) or absent. Reporting `Unknown` for them was the `v0.2`-era bug
/// this guards: a bundle made only of configuration resources would report an unreadable
/// `Application` health forever.
#[derive(Debug, Clone, Copy)]
pub struct PassiveHealth {
    kind: &'static str,
}

impl PassiveHealth {
    /// Builds a passive evaluator naming its kind in the message.
    #[must_use]
    pub const fn new(kind: &'static str) -> Self {
        Self { kind }
    }
}

impl HealthEvaluator for PassiveHealth {
    fn evaluate(&self, _object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        ResourceHealth::healthy(format!("{} exists", self.kind))
    }
}

/// `CustomResourceDefinition` health: `Healthy` once the API server reports `Established=True`.
///
/// Never `Unknown` (`T09.1` trap guard): a CRD that has not been observed yet is `Progressing`,
/// because the API server is actively registering it.
#[derive(Debug, Clone, Copy)]
pub struct CustomResourceDefinitionHealth;

impl HealthEvaluator for CustomResourceDefinitionHealth {
    fn evaluate(&self, object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
        let conditions = values::conditions(object);
        match values::condition(&conditions, "Established") {
            Some(condition) if condition.is_true() => {
                ResourceHealth::healthy("CustomResourceDefinition is established")
            }
            Some(condition) if condition.is_false() => ResourceHealth::progressing(format!(
                "waiting for the API server to establish the CustomResourceDefinition ({})",
                condition.describe()
            )),
            Some(_) => ResourceHealth::progressing(
                "waiting for the API server to establish the CustomResourceDefinition",
            ),
            None => ResourceHealth::progressing(
                "CustomResourceDefinition has not reported an Established condition yet",
            ),
        }
    }
}

/// How the controller observed one managed resource in this pass.
///
/// The live object was read *before* this pass applied anything, so an object created by this very
/// pass has no observation yet. Modelling that explicitly keeps a just-created `Deployment` from
/// being reported `Missing` (which would be a lie: it exists as of the apply that just succeeded).
#[derive(Clone, Debug)]
pub enum Observation<'a> {
    /// The live object as read from the API server.
    Live(&'a DynamicObject),
    /// The object does not exist.
    Missing,
    /// The object was applied by this pass, so the pass-level live read predates the write.
    AppliedAwaitingObservation,
    /// The object cannot be observed yet (a pending `CustomResourceDefinition` or `Namespace`).
    Pending(String),
}

/// One resource to assess.
#[derive(Clone, Debug)]
pub struct HealthInput<'a> {
    /// Version-agnostic identity of the resource.
    pub key: &'a ResourceKey,
    /// What this pass knows about it.
    pub observation: Observation<'a>,
}

impl<'a> HealthInput<'a> {
    /// A resource observed live.
    #[must_use]
    pub fn live(key: &'a ResourceKey, object: &'a DynamicObject) -> Self {
        Self {
            key,
            observation: Observation::Live(object),
        }
    }

    /// A desired resource that does not exist.
    #[must_use]
    pub fn missing(key: &'a ResourceKey) -> Self {
        Self {
            key,
            observation: Observation::Missing,
        }
    }

    /// A resource this pass just applied.
    #[must_use]
    pub fn applied(key: &'a ResourceKey) -> Self {
        Self {
            key,
            observation: Observation::AppliedAwaitingObservation,
        }
    }

    /// A resource waiting on a `CustomResourceDefinition` or a `Namespace`.
    #[must_use]
    pub fn pending(key: &'a ResourceKey, message: impl Into<String>) -> Self {
        Self {
            key,
            observation: Observation::Pending(message.into()),
        }
    }
}

/// Health of one resource, with its identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceAssessment {
    /// Version-agnostic identity of the resource.
    pub key: ResourceKey,
    /// The verdict for this resource.
    pub health: ResourceHealth,
}

/// Aggregated health of a resource set, ready to be persisted on `Application.status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthSummary {
    /// Worst resource verdict (an empty set is [`HealthStatus::Healthy`]).
    pub status: HealthStatus,
    /// Bounded, deterministic, secret-free explanation.
    pub message: String,
    /// Per-resource verdicts, sorted by [`ResourceKey`] so two passes over the same cluster
    /// produce byte-identical `/status` payloads.
    pub resources: Vec<ResourceAssessment>,
}

impl HealthSummary {
    /// Returns whether every resource is healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.status == HealthStatus::Healthy
    }

    /// Returns whether any resource is still converging, i.e. whether the controller should poll
    /// faster (`T09.5` adaptive requeue).
    #[must_use]
    pub fn is_progressing(&self) -> bool {
        self.status == HealthStatus::Progressing
    }

    /// Number of resources whose verdict is not `Healthy`.
    #[must_use]
    pub fn unhealthy_count(&self) -> usize {
        self.resources
            .iter()
            .filter(|assessment| !assessment.health.is_healthy())
            .count()
    }
}

/// Assesses a resource set and aggregates the verdicts.
///
/// The result is deterministic: inputs are evaluated independently and the per-resource list is
/// sorted by [`ResourceKey`], so the aggregate and the message never depend on map iteration order.
#[must_use]
pub fn assess(
    inputs: &[HealthInput<'_>],
    registry: &HealthRegistry,
    config: &HealthConfig,
) -> HealthSummary {
    let mut resources: Vec<ResourceAssessment> = inputs
        .iter()
        .map(|input| ResourceAssessment {
            key: input.key.clone(),
            health: evaluate_input(input, registry, config),
        })
        .collect();
    resources.sort_by(|left, right| left.key.cmp(&right.key));

    let status = aggregate(resources.iter().map(|assessment| assessment.health.status));
    let message = summary_message(status, &resources);
    HealthSummary {
        status,
        message,
        resources,
    }
}

/// Evaluates one observation.
fn evaluate_input(
    input: &HealthInput<'_>,
    registry: &HealthRegistry,
    config: &HealthConfig,
) -> ResourceHealth {
    match &input.observation {
        Observation::Live(object) => registry.evaluate(input.key, object, config),
        Observation::Missing => {
            ResourceHealth::missing(format!("{} does not exist", input.key.kind))
        }
        Observation::AppliedAwaitingObservation => ResourceHealth::progressing(
            "applied in this pass; waiting for the API server to report it",
        ),
        Observation::Pending(message) => ResourceHealth::progressing(message.clone()),
    }
}

/// Builds the bounded, deterministic `status.health.message`.
fn summary_message(status: HealthStatus, resources: &[ResourceAssessment]) -> String {
    let total = resources.len();
    if total == 0 {
        return "no managed resources".to_owned();
    }
    if status == HealthStatus::Healthy {
        return format!("all {total} resource(s) are healthy");
    }

    let unhealthy = resources
        .iter()
        .filter(|assessment| !assessment.health.is_healthy())
        .count();
    // Deterministic "worst first": the sorted list already fixes the tie-break, and the aggregate
    // status is the worst verdict present, so this is the first resource carrying it.
    let worst = resources
        .iter()
        .find(|assessment| assessment.health.status == status);

    let message = match worst {
        Some(worst) => format!(
            "{unhealthy} of {total} resource(s) are not Healthy: {} is {}: {}",
            worst.key.canonical(),
            status_label(status),
            worst.health.message
        ),
        None => format!(
            "{unhealthy} of {total} resource(s) are {}",
            status_label(status)
        ),
    };
    truncate_message(&message)
}

/// Truncates `message` to [`MAX_STATUS_MESSAGE_CHARS`] on a UTF-8 boundary.
///
/// `/status` is capped by `etcd`, and a third-party controller's condition message is unbounded
/// free-form text, so the engine bounds it before it ever reaches `Application.status`. Shared with
/// the Phase 10 operation/history writers, which put messages in the same budgeted `/status`.
pub(crate) fn truncate_message(message: &str) -> String {
    if message.chars().count() <= MAX_STATUS_MESSAGE_CHARS {
        return message.to_owned();
    }
    let mut truncated: String = message.chars().take(MAX_STATUS_MESSAGE_CHARS).collect();
    truncated.push('…');
    truncated
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn object(value: serde_json::Value) -> DynamicObject {
        serde_json::from_value(value).expect("valid DynamicObject")
    }

    fn key(group: &str, kind: &str, name: &str) -> ResourceKey {
        ResourceKey::new(group, kind, Some("payments".to_owned()), name)
    }

    const ALL: [HealthStatus; 6] = [
        HealthStatus::Healthy,
        HealthStatus::Progressing,
        HealthStatus::Degraded,
        HealthStatus::Suspended,
        HealthStatus::Missing,
        HealthStatus::Unknown,
    ];

    /// The documented order, spelled out independently of `precedence`.
    const EXPECTED_ORDER: [HealthStatus; 6] = [
        HealthStatus::Healthy,
        HealthStatus::Unknown,
        HealthStatus::Suspended,
        HealthStatus::Progressing,
        HealthStatus::Missing,
        HealthStatus::Degraded,
    ];

    /// Total order: every pair aggregates to the higher-ranked status, in both orders.
    #[test]
    fn the_lattice_is_a_strict_total_order() {
        for (low_index, low) in EXPECTED_ORDER.iter().enumerate() {
            for high in &EXPECTED_ORDER[low_index + 1..] {
                assert!(
                    precedence(*high) > precedence(*low),
                    "{high:?} must outrank {low:?}"
                );
                assert_eq!(aggregate([*low, *high]), *high);
                assert_eq!(
                    aggregate([*high, *low]),
                    *high,
                    "aggregation must not depend on input order"
                );
            }
        }
        let mut worst_first = EXPECTED_ORDER;
        worst_first.reverse();
        assert_eq!(
            PRECEDENCE_ORDER, worst_first,
            "PRECEDENCE_ORDER documents the same order as precedence()"
        );
    }

    /// Every one of the 64 subsets aggregates to its maximum, and duplicates change nothing.
    #[test]
    fn every_subset_aggregates_to_its_worst_member() {
        for mask in 0_u32..(1 << ALL.len()) {
            let mut subset: Vec<HealthStatus> = Vec::new();
            for (index, status) in ALL.iter().enumerate() {
                if mask & (1 << index) != 0 {
                    subset.push(*status);
                }
            }

            let expected = subset
                .iter()
                .copied()
                .max_by_key(|status| precedence(*status))
                .unwrap_or(HealthStatus::Healthy);
            assert_eq!(
                aggregate(subset.iter().copied()),
                expected,
                "subset {subset:?} must aggregate to {expected:?}"
            );

            // Reversed and duplicated inputs must not change the verdict.
            let mut reversed: Vec<HealthStatus> = subset.iter().rev().copied().collect();
            reversed.extend(subset.iter().copied());
            assert_eq!(aggregate(reversed), expected);
        }
        assert_eq!(
            aggregate(std::iter::empty()),
            HealthStatus::Healthy,
            "an empty resource set is Healthy"
        );
    }

    #[test]
    fn labels_are_stable_wire_words() {
        assert_eq!(status_label(HealthStatus::Healthy), "Healthy");
        assert_eq!(status_label(HealthStatus::Progressing), "Progressing");
        assert_eq!(status_label(HealthStatus::Degraded), "Degraded");
        assert_eq!(status_label(HealthStatus::Suspended), "Suspended");
        assert_eq!(status_label(HealthStatus::Missing), "Missing");
        assert_eq!(status_label(HealthStatus::Unknown), "Unknown");
    }

    /// `T09.1` trap guard: a bundle of configuration resources is Health**, never `Unknown`.
    #[test]
    fn passive_resources_are_healthy_and_never_unknown() {
        let registry = HealthRegistry::builtin();
        let config = HealthConfig::default();
        for (group, kind) in [
            ("", "ConfigMap"),
            ("", "Secret"),
            ("", "ServiceAccount"),
            ("", "Namespace"),
            ("rbac.authorization.k8s.io", "Role"),
            ("rbac.authorization.k8s.io", "ClusterRole"),
            ("rbac.authorization.k8s.io", "RoleBinding"),
            ("rbac.authorization.k8s.io", "ClusterRoleBinding"),
        ] {
            assert!(
                registry.handles(group, kind),
                "{group}/{kind} must be built in"
            );
            // Deliberately an object with no status at all: passive kinds have none.
            let live = object(json!({
                "apiVersion": if group.is_empty() { "v1".to_owned() } else { format!("{group}/v1") },
                "kind": kind,
                "metadata": { "name": "settings" },
            }));
            let health = registry.evaluate(&key(group, kind, "settings"), &live, &config);
            assert_eq!(health.status, HealthStatus::Healthy, "{group}/{kind}");
            assert_ne!(health.status, HealthStatus::Unknown, "{group}/{kind}");
            assert!(health.message.contains(kind), "{}", health.message);
        }
    }

    /// A `Secret` may carry credentials, so its health must never quote them.
    #[test]
    fn passive_secret_health_never_echoes_its_payload() {
        let registry = HealthRegistry::builtin();
        let live = object(json!({
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": { "name": "creds" },
            "data": { "password": "aHVudGVyMg==" },
        }));
        let health =
            registry.evaluate(&key("", "Secret", "creds"), &live, &HealthConfig::default());
        assert_eq!(health.status, HealthStatus::Healthy);
        assert!(!health.message.contains("aHVudGVyMg"), "{}", health.message);
    }

    #[test]
    fn a_custom_resource_definition_is_progressing_until_it_is_established() {
        let registry = HealthRegistry::builtin();
        let config = HealthConfig::default();
        let crd_key = key(
            "apiextensions.k8s.io",
            "CustomResourceDefinition",
            "widgets",
        );

        let not_established = object(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "status": { "conditions": [
                { "type": "NamesAccepted", "status": "True", "reason": "NoConflicts" },
                { "type": "Established", "status": "False", "reason": "Installing" },
            ] },
        }));
        assert_eq!(
            registry
                .evaluate(&crd_key, &not_established, &config)
                .status,
            HealthStatus::Progressing
        );

        let no_conditions = object(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
        }));
        assert_eq!(
            registry.evaluate(&crd_key, &no_conditions, &config).status,
            HealthStatus::Progressing,
            "a fresh CRD is converging, never Unknown"
        );

        let established = object(json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": { "name": "widgets.example.com" },
            "status": { "conditions": [
                { "type": "Established", "status": "True", "reason": "InitialNamesAccepted" },
            ] },
        }));
        assert_eq!(
            registry.evaluate(&crd_key, &established, &config).status,
            HealthStatus::Healthy
        );
    }

    #[test]
    fn the_registry_falls_back_to_the_generic_condition_heuristic() {
        let registry = HealthRegistry::builtin();
        assert!(!registry.handles("example.com", "Widget"));
        let ready = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one" },
            "status": { "conditions": [
                { "type": "Ready", "status": "True", "reason": "Available" },
            ] },
        }));
        let health = registry.evaluate(
            &key("example.com", "Widget", "one"),
            &ready,
            &HealthConfig::default(),
        );
        assert_eq!(health.status, HealthStatus::Healthy);
    }

    #[test]
    fn custom_evaluators_can_be_registered_for_any_kind() {
        #[derive(Debug)]
        struct AlwaysDegraded;
        impl HealthEvaluator for AlwaysDegraded {
            fn evaluate(&self, _object: &DynamicObject, _config: &HealthConfig) -> ResourceHealth {
                ResourceHealth::degraded("widget is wedged")
            }
        }

        let mut registry = HealthRegistry::builtin();
        registry.insert("example.com", "Widget", AlwaysDegraded);
        assert!(registry.handles("example.com", "Widget"));
        let live = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one" },
        }));
        assert_eq!(
            registry
                .evaluate(
                    &key("example.com", "Widget", "one"),
                    &live,
                    &HealthConfig::default()
                )
                .status,
            HealthStatus::Degraded
        );
    }

    #[test]
    fn observations_map_onto_the_expected_verdicts() {
        let registry = HealthRegistry::builtin();
        let config = HealthConfig::default();
        let config_map = key("", "ConfigMap", "settings");
        let live = object(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "settings" },
        }));

        let summary = assess(
            &[
                HealthInput::live(&config_map, &live),
                HealthInput::missing(&key("", "Secret", "creds")),
                HealthInput::applied(&key("apps", "Deployment", "api")),
                HealthInput::pending(&key("example.com", "Widget", "one"), "waiting for the CRD"),
            ],
            &registry,
            &config,
        );

        assert_eq!(summary.status, HealthStatus::Missing);
        assert_eq!(
            summary.resources.len(),
            4,
            "every input must be represented"
        );
        assert_eq!(
            summary
                .resources
                .iter()
                .map(|assessment| assessment.key.canonical())
                .collect::<Vec<_>>(),
            vec![
                "/ConfigMap/payments/settings",
                "/Secret/payments/creds",
                "apps/Deployment/payments/api",
                "example.com/Widget/payments/one",
            ],
            "assessments are sorted by ResourceKey (byte-stable /status)"
        );
        assert_eq!(summary.unhealthy_count(), 3);
        assert!(!summary.is_healthy());
        assert!(!summary.is_progressing());

        let applied = summary
            .resources
            .iter()
            .find(|assessment| assessment.key.kind == "Deployment")
            .expect("deployment assessment");
        assert_eq!(applied.health.status, HealthStatus::Progressing);
        assert!(applied.health.message.contains("applied in this pass"));
    }

    #[test]
    fn an_empty_resource_set_is_healthy() {
        let summary = assess(&[], &HealthRegistry::builtin(), &HealthConfig::default());
        assert_eq!(summary.status, HealthStatus::Healthy);
        assert!(summary.is_healthy());
        assert_eq!(summary.message, "no managed resources");
        assert!(summary.resources.is_empty());
    }

    #[test]
    fn the_summary_message_is_deterministic_bounded_and_actionable() {
        let registry = HealthRegistry::builtin();
        let config = HealthConfig::default();
        let healthy = object(json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "settings" },
        }));
        let healthy_key = key("", "ConfigMap", "settings");
        let summary = assess(
            &[HealthInput::live(&healthy_key, &healthy)],
            &registry,
            &config,
        );
        assert_eq!(summary.message, "all 1 resource(s) are healthy");

        // A CR whose condition message is pathologically long must not bloat /status.
        let long = "x".repeat(MAX_STATUS_MESSAGE_CHARS * 2);
        let noisy = object(json!({
            "apiVersion": "example.com/v1",
            "kind": "Widget",
            "metadata": { "name": "one" },
            "status": { "conditions": [
                { "type": "Ready", "status": "False", "reason": "ReconcileFailed", "message": long },
            ] },
        }));
        let noisy_key = key("example.com", "Widget", "one");
        let summary = assess(&[HealthInput::live(&noisy_key, &noisy)], &registry, &config);
        assert_eq!(summary.status, HealthStatus::Degraded);
        assert!(
            summary.message.chars().count() <= MAX_STATUS_MESSAGE_CHARS + 1,
            "{} chars",
            summary.message.chars().count()
        );
        assert!(
            summary
                .message
                .contains("example.com/Widget/payments/one is Degraded"),
            "the worst resource must be named: {}",
            summary.message
        );
        assert_eq!(
            summary.message,
            assess(&[HealthInput::live(&noisy_key, &noisy)], &registry, &config).message,
            "two identical passes must produce an identical message"
        );
    }
}
