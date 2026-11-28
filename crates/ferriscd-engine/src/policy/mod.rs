//! Tenancy policy: `AppProject` allow-list enforcement and the Apps-in-any-namespace scope.
//!
//! Phase 12 replaces the `PermissivePolicy` stub of Phases 05–11 with two cooperating pieces that
//! stay **pure and offline** (the controller does the fetching, so everything here is a unit test):
//!
//! * [`AppProjectPolicy`] — the `AppProject` allow-lists, checked once *before* rendering and again
//!   on **every** rendered resource after Stage-2 scope normalization (`T12.1`).
//! * [`ApplicationScope`] — which namespaces may host `Application` objects at all, plus the tenant
//!   guard that refuses to reconcile a tenant `Application` without its own `serviceAccountName`
//!   (`T12.2`, ADR-007).
//!
//! Both fail closed: a missing project, an unlisted repository, a manifest that hardcodes
//! `metadata.namespace: kube-system`, or an unlisted cluster-scoped kind is a **terminal**
//! [`PolicyError`], never a silent allow.

pub mod app_project;
pub mod cel;
pub mod gate;
pub mod namespace_scope;
#[cfg(feature = "opa-policy")]
pub mod rego;

pub use app_project::{AppProjectPolicy, PolicyError, wildcard_matches};
pub use cel::{CelBudget, CelError, CelFailure, Program};
// The wire-level enums live in `ferriscd-crd` (they are part of the CRD schema); the engine
// re-exports them so a caller never has to depend on both crates to build a rule.
pub use ferriscd_crd::project::{PolicyEnforcement, PolicyRuleEngine, PolicyRuleSpec};
pub use gate::{
    CONDITION_POLICY_ADVISORY, MAX_CONDITION_ADVISORIES, MAX_POLICY_RESOURCES, MAX_POLICY_RULES,
    MAX_POLICY_VIOLATIONS, POLICY_CONFIGMAP_NAME, PolicyCompileError, PolicyGate, PolicyGateConfig,
    PolicyGateInput, PolicyGateOutcome, PolicyRule, PolicyRuleParseError, PolicyViolation,
    REASON_POLICY_ADVISORY, REASON_POLICY_COMPLIANT, REDACTED_SECRET_VALUE, RegoEvaluator,
    RegoPassBudget, invalid_match_kinds, normalize_match_kind, normalize_match_kinds,
    policy_advisory_condition, redact_secret_values, rules_from_configmap_data,
};
pub use namespace_scope::{
    ALL_NAMESPACES, ApplicationNamespaces, ApplicationScope, ApplicationScopeError,
};
#[cfg(feature = "opa-policy")]
pub use rego::{RegoLimits, RegorusEvaluator};
