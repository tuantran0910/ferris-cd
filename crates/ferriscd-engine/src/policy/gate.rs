//! Pre-sync **policy-as-code gate** (`T20.2`).
//!
//! [`AppProjectPolicy`](super::AppProjectPolicy) answers "may this `Application` deploy *that
//! kind* into *that namespace*". This module answers the finer question a security team actually
//! asks: "is the *content* of every rendered manifest acceptable" — no `privileged: true`, only
//! images from the approved registry, a `cost-center` label, a `PodDisruptionBudget` for a
//! production `Deployment`.
//!
//! # Where it sits
//!
//! The gate runs **immediately after Stage-2 scope normalization** (so it sees the same namespaces
//! and kinds the applier will) and **before** the live read, the `dryRun=All` diff, every SSA
//! apply, and every prune. An `Enforce` violation is a terminal refusal, so a non-compliant bundle
//! costs the cluster nothing.
//!
//! # The engine is pure
//!
//! [`PolicyGate::evaluate`] is a synchronous, deterministic function of its [`PolicyGateInput`]:
//! no cluster call, no clock, no process, no filesystem, no network, no randomness. That is what
//! makes it a unit test rather than an integration test — and what makes the control-plane API's
//! read-only `GET .../diff` able to report the same verdict the next reconcile will.
//!
//! # Cost is bounded, and the bound is a counter
//!
//! Every expression compiles under a [`CelBudget`] (byte, AST-node, depth, fuel, output sizes) and
//! the whole evaluation runs under a total step budget. Exhausting a budget is a **failure**, and
//! a failure is a violation — never an allow. Because the budget is a step counter, a malformed
//! policy's "timeout" is reproducible in a unit test without sleeping.
//!
//! # Fail closed, always
//!
//! | Situation | Verdict |
//! |---|---|
//! | expression does not compile | `Enforce` violation, whatever the rule's `enforcement` says |
//! | expression evaluates to a non-boolean | `Enforce` violation |
//! | evaluation errors (type mismatch, missing field) | `Enforce` violation |
//! | fuel / node / step budget exhausted | `Enforce` violation |
//! | expression evaluates to `false` | violation with the rule's own `enforcement` |
//! | expression evaluates to `true` | no violation |
//!
//! The first four rows are the trap guard: a rule that cannot be understood or cannot finish can
//! never silently degrade into "allow". Turning a compile error into an advisory would be exactly
//! the fail-open the roadmap forbids, so it is refused even for a `Warn` rule.
//!
//! # A `Warn` rule advises on its *verdict*, never on its *failures*
//!
//! `enforcement: Warn` downgrades exactly one thing: an expression that evaluates cleanly to
//! `false`. Everything else about the rule still blocks — an expression that does not compile, an
//! evaluation that errors (a type mismatch, a missing field, a budget), a non-boolean result, and an
//! engine this build cannot provide (`Rego` without an evaluator). The distinction matters because
//! each of those means *the rule did not run*, and a rule that did not run cannot be said to have
//! been satisfied: treating it as an advisory would let a typo in a `Warn` policy silently disable
//! it while the sync continues, which is the same bypass as deleting the rule.
//!
//! # Secrets never reach the evaluator
//!
//! A `v1/Secret` is handed to the evaluator with its `data`/`stringData` **values** replaced by
//! [`REDACTED_SECRET_VALUE`] — a policy sees the metadata, the `type`, and the key names, never a
//! payload. As a second line of defense every violation message is scrubbed against the plaintext
//! (and base64) forms gathered from the bundle before it is emitted ([`redact_secret_values`]), so
//! even a message assembled from a buggy policy or a CEL diagnostic cannot exfiltrate a value.
//! That scrub is best-effort by design: see [`collect_secret`] for the documented caveat about
//! payloads shorter than four bytes (which the redacted view never exposes in the first place).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use dashmap::DashMap;
use ferriscd_crd::project::{PolicyEnforcement, PolicyRuleEngine, PolicyRuleSpec, WILDCARD};
use ferriscd_crd::status::{Condition, ConditionStatus};
use ferriscd_crd::{Application, CONTROL_PLANE_NAMESPACE};
use kube::ResourceExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::app_project::wildcard_matches;
use super::cel::{self, CelBudget, CelError, Program};
use crate::manifest::{DesiredResource, parse_document};

/// `Application.status.conditions[].type` carrying the `Warn` advisories of a pass.
pub const CONDITION_POLICY_ADVISORY: &str = "PolicyAdvisory";

/// Reason of the `PolicyAdvisory=True` condition.
pub const REASON_POLICY_ADVISORY: &str = "PolicyAdvisory";

/// Reason of the `PolicyAdvisory=False` condition (a pass with no advisories).
pub const REASON_POLICY_COMPLIANT: &str = "PolicyCompliant";

/// The value a `Secret` payload is replaced with before policy evaluation.
pub const REDACTED_SECRET_VALUE: &str = "<redacted>";

/// The `ConfigMap` a cluster administrator configures cluster-wide policy rules in.
pub const POLICY_CONFIGMAP_NAME: &str = "ferriscd-policies-cm";

/// Maximum number of rules one `Application` is evaluated against — **in total**.
///
/// A bound, not a suggestion. The rule set of one `Application` is the union of
/// `AppProject.spec.policyRules[]` and `ConfigMap/ferriscd-policies-cm`, and *both* count against
/// this one number: the controller refuses the pass when the project list or the union overflows
/// (see `PolicyRule::set_from_project_spec` and the controller's `policy_gate_for`), so "32 project
/// rules plus 40 cluster-wide rules" is a refusal, never a silently narrowed rule set. Over the
/// bound the gate *also* fails closed here, so no caller can evaluate a truncated list by accident.
pub const MAX_POLICY_RULES: usize = 32;

/// Maximum number of rendered resources one pass evaluates.
///
/// A bundle over this bound fails closed: skipping resources would be a policy bypass.
pub const MAX_POLICY_RESOURCES: usize = 2_000;

/// Maximum number of violations reported for one pass.
///
/// Violations reach `Application.status`, which must stay small (trap T9).
pub const MAX_POLICY_VIOLATIONS: usize = 32;

/// Maximum length of one violation message.
pub const MAX_POLICY_MESSAGE_CHARS: usize = 512;

/// Maximum number of advisories spelled out in the `PolicyAdvisory` condition message.
///
/// The condition shares `Application.status`'s budget with every other condition (trap T9), so its
/// message is built from a capped list — five advisories, then a `(+N more)` count — instead of
/// joining every retained violation and truncating the result afterwards.
pub const MAX_CONDITION_ADVISORIES: usize = 5;

/// Maximum number of compiled programs held in the per-pipeline cache.
pub const MAX_CACHED_PROGRAMS: usize = 256;

/// Total fuel **one pass** (one [`PolicyGate::evaluate`] call) may spend, across every rule and
/// resource in the bundle.
///
/// Deterministic: it caps the CPU one pass can spend on policy no matter how the operator wrote the
/// rules, which is the "strict per-expression step/fuel limit" requirement of `T20.2`. It is not a
/// per-evaluation allowance — [`CelBudget::steps`] is — so `rules × resources` cannot multiply it.
pub const DEFAULT_TOTAL_STEPS: u64 = 2_000_000;

/// Returns the [`PolicyEnforcement`] of a rule.
pub use ferriscd_crd::project::PolicyEnforcement as Enforcement;

/// One compiled-or-not policy rule, reduced to what the gate needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRule {
    /// Rule name (unique within a rule set; it names the rule in every message).
    pub name: String,
    /// `Enforce` or `Warn`.
    pub enforcement: PolicyEnforcement,
    /// Expression engine.
    pub engine: PolicyRuleEngine,
    /// GroupKind globs (`*`, `Kind`, `group/Kind`, `group/*`); empty matches everything.
    pub match_kinds: Vec<String>,
    /// The first `matchKinds` entry that can never match a GroupKind, if the rule was given one.
    ///
    /// A pattern like `v1` or `apps/v1` names an `apiVersion` without a Kind, so it matches
    /// **nothing** — and a rule that matches nothing allows everything, which is a policy bypass
    /// that looks like a typo. It is recorded here, at construction, because normalization (which
    /// is what keeps `v1/Secret` working) would otherwise erase the evidence; the gate refuses a
    /// rule that carries one.
    pub invalid_match_kind: Option<String>,
    /// The invariant that must hold.
    pub expression: String,
    /// Operator-facing violation text.
    pub message: Option<String>,
}

impl PolicyRule {
    /// Builds a rule (used by the [`PolicyGateInput`] tests and by the controller wiring).
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        enforcement: PolicyEnforcement,
        expression: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            enforcement,
            engine: PolicyRuleEngine::Cel,
            match_kinds: Vec::new(),
            invalid_match_kind: None,
            expression: expression.into(),
            message: None,
        }
    }

    /// Restricts the rule to `match_kinds`, normalizing `apiVersion`-shaped patterns.
    #[must_use]
    pub fn with_match_kinds(mut self, match_kinds: Vec<String>) -> Self {
        self.invalid_match_kind = invalid_match_kinds(&match_kinds);
        self.match_kinds = normalize_match_kinds(match_kinds);
        self
    }

    /// Sets the operator-facing message.
    #[must_use]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// Sets the expression engine.
    #[must_use]
    pub fn with_engine(mut self, engine: PolicyRuleEngine) -> Self {
        self.engine = engine;
        self
    }

    /// Converts the whole project rule list, reporting whether it had to be capped.
    ///
    /// There is deliberately **no** infallible "convert the list" constructor: silently keeping the
    /// first [`MAX_POLICY_RULES`] entries of a longer list is a policy bypass, so the overflow is
    /// always reported and the caller always has to refuse the pass.
    #[must_use]
    pub fn set_from_project_spec(specs: &[PolicyRuleSpec]) -> (Vec<Self>, bool) {
        let rules: Vec<Self> = specs
            .iter()
            .take(MAX_POLICY_RULES)
            .map(Self::from_spec)
            .collect();
        let overflowed = specs.len() > rules.len();
        (rules, overflowed)
    }

    fn from_spec(spec: &PolicyRuleSpec) -> Self {
        Self {
            name: spec.name.clone(),
            enforcement: spec.enforcement,
            engine: spec.engine.unwrap_or_default(),
            match_kinds: normalize_match_kinds(spec.match_kinds.clone()),
            invalid_match_kind: invalid_match_kinds(&spec.match_kinds),
            expression: spec.expression.clone(),
            message: spec.message.clone(),
        }
    }

    /// Whether this rule applies to `(group, kind)`.
    ///
    /// Matching uses the same deterministic glob engine as the project allow-lists
    /// ([`wildcard_matches`]), so `*`, `Deployment`, `apps/Deployment`, and `batch/*` all behave the
    /// way an operator already expects. An empty list matches every kind.
    ///
    /// An `apiVersion`-shaped pattern (`v1/Secret`, `apps/v1/Deployment`) is normalized first — see
    /// [`normalize_match_kinds`], which is what keeps a rule written in manifest shape from matching
    /// nothing and silently allowing everything.
    #[must_use]
    pub fn matches_kind(&self, group: &str, kind: &str) -> bool {
        if self.match_kinds.is_empty() {
            return true;
        }
        let qualified = format!("{group}/{kind}");
        self.match_kinds.iter().any(|pattern| {
            let normalized = normalize_match_kind(pattern);
            let pattern = normalized.trim();
            if pattern == WILDCARD {
                return true;
            }
            if pattern.contains('/') {
                wildcard_matches(pattern, &qualified)
            } else {
                wildcard_matches(pattern, kind)
            }
        })
    }
}

/// Rewrites every `matchKinds` entry that spells an `apiVersion` into its GroupKind form.
///
/// `matchKinds` is documented as `Kind`, `group/Kind`, `group/*`, or `*` — but a manifest's own
/// `apiVersion: v1` / `apps/v1` is right next to `kind: Secret`, so `v1/Secret` is the natural
/// mistake. Matching it against `""/Secret` (or `apps/Deployment`) would match **nothing**, and a
/// rule that matches nothing allows everything: a policy bypass that looks like a typo. A version
/// segment is therefore dropped rather than rejected, because there is no ambiguity — no Kubernetes
/// group is named like an `apiVersion`.
///
/// A pattern that names **only** an `apiVersion` (`v1`, `apps/v1`) has no Kind to keep and cannot be
/// rewritten into anything meaningful; it is recorded by [`invalid_match_kinds`] and the gate
/// refuses the rule instead of letting it match nothing.
#[must_use]
pub fn normalize_match_kinds(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .map(|pattern| normalize_match_kind(&pattern).into_owned())
        .collect()
}

/// The first `matchKinds` entry that can never match a GroupKind, if any.
///
/// Two shapes are unmatchable:
///
/// * an empty (or whitespace-only) pattern, and
/// * a pattern whose **last** non-empty segment is an `apiVersion` (`v1`, `apps/v1`, `v1/`), i.e. a
///   pattern that names no Kind at all.
///
/// Both would make [`PolicyRule::matches_kind`] answer `false` for every resource, and a rule that
/// matches nothing allows everything — so the gate refuses such a rule (fail closed) instead of
/// trusting the operator to notice that their policy silently stopped applying.
///
/// It is checked on the **raw** patterns, before [`normalize_match_kinds`] drops the version
/// segment: after normalization `apps/v1` would look like a Kind named `apps`.
#[must_use]
pub fn invalid_match_kinds(patterns: &[String]) -> Option<String> {
    patterns
        .iter()
        .find(|pattern| {
            let last = pattern
                .split('/')
                .map(str::trim)
                .rfind(|segment| !segment.is_empty());
            last.is_none_or(is_api_version)
        })
        .cloned()
}

/// Normalizes one `matchKinds` pattern, borrowing when there is nothing to rewrite.
#[must_use]
pub fn normalize_match_kind(pattern: &str) -> Cow<'_, str> {
    let segments: Vec<&str> = pattern.split('/').collect();
    if segments.len() < 2 || !segments.iter().any(|segment| is_api_version(segment)) {
        return Cow::Borrowed(pattern);
    }
    let kept: Vec<&str> = segments
        .into_iter()
        .filter(|segment| !is_api_version(segment))
        .collect();
    Cow::Owned(kept.join("/"))
}

/// Whether `segment` is a Kubernetes API version (`v1`, `v2beta1`, `v1alpha2`).
///
/// Deliberately anchored and numeric: `apps`, `batch`, and every Kind start with a letter, so only
/// a real version is rewritten.
fn is_api_version(segment: &str) -> bool {
    let Some(rest) = segment.strip_prefix('v') else {
        return false;
    };
    let digits = rest
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(rest.len());
    if digits == 0 {
        return false;
    }
    let (_, suffix) = rest.split_at(digits);
    if suffix.is_empty() {
        return true;
    }
    for qualifier in ["alpha", "beta"] {
        if let Some(tail) = suffix.strip_prefix(qualifier) {
            return !tail.is_empty() && tail.chars().all(|character| character.is_ascii_digit());
        }
    }
    false
}

/// The wire form of one `ConfigMap/ferriscd-policies-cm` entry.
///
/// The key is the rule name, the value is a YAML (or JSON — YAML is a superset) document holding
/// everything but the name:
///
/// ```yaml
/// # ConfigMap/ferriscd-policies-cm, data:
/// no-privileged-containers: |
///   enforcement: Enforce
///   matchKinds: ["apps/Deployment", "apps/StatefulSet", "apps/DaemonSet"]
///   expression: "!object.spec.template.spec.containers.exists(c, has(c.securityContext) && c.securityContext.privileged == true)"
///   message: "privileged containers are forbidden"
/// no-privileged-pods: |
///   enforcement: Enforce
///   matchKinds: ["Pod"]
///   expression: "!object.spec.containers.exists(c, has(c.securityContext) && c.securityContext.privileged == true)"
///   message: "privileged pods are forbidden"
/// ```
///
/// `matchKinds` and `expression` have to agree, because `object` is *the matched resource*: `Pod`
/// keeps its containers at `spec.containers`, a workload keeps them at `spec.template.spec.…`. A
/// path the matched kind does not carry is not "no match" — it is an evaluation **error**, and the
/// gate treats an evaluation error as a blocking violation even for a `Warn` rule. Write one rule
/// per shape, or guard the optional part of the path with `has(...)`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyRuleDocument {
    #[serde(default)]
    enforcement: PolicyEnforcement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    engine: Option<PolicyRuleEngine>,
    #[serde(default)]
    match_kinds: Vec<String>,
    expression: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Why a `ConfigMap/ferriscd-policies-cm` entry could not be read as a rule.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyRuleParseError {
    /// The entry is not a valid rule document (or is over the YAML budgets).
    #[error("policy rule {rule:?} in {configmap} is not a valid rule document")]
    Invalid {
        /// The `ConfigMap` name.
        configmap: String,
        /// The entry key.
        rule: String,
    },

    /// The rule has no `expression`.
    #[error("policy rule {rule:?} in {configmap} has an empty expression")]
    EmptyExpression {
        /// The `ConfigMap` name.
        configmap: String,
        /// The entry key.
        rule: String,
    },

    /// One `matchKinds` entry names an `apiVersion` but no Kind, so it could never match.
    #[error(
        "policy rule {rule:?} in {configmap} has an unmatchable matchKinds entry {pattern:?}: it \
         names an apiVersion, not a Kind, so the rule would match nothing and allow everything"
    )]
    InvalidMatchKind {
        /// The `ConfigMap` name.
        configmap: String,
        /// The entry key.
        rule: String,
        /// The offending pattern, verbatim.
        pattern: String,
    },
}

/// Parses the `data` of `ConfigMap/ferriscd-policies-cm` into rules.
///
/// Pure: the caller (the controller) does the API read and hands the `data` map in. Entries are
/// read in key order, so the resulting rule order — and therefore every violation message — is
/// deterministic for a given `ConfigMap`.
///
/// # Errors
///
/// [`PolicyRuleParseError`] for a malformed entry. The caller must fail closed: a `ConfigMap` the
/// controller cannot parse must never mean "no rules".
pub fn rules_from_configmap_data(
    configmap: &str,
    data: &BTreeMap<String, String>,
) -> Result<Vec<PolicyRule>, PolicyRuleParseError> {
    let mut rules = Vec::new();
    for (key, value) in data {
        let document: PolicyRuleDocument =
            parse_document(value).map_err(|_| PolicyRuleParseError::Invalid {
                configmap: configmap.to_owned(),
                rule: key.clone(),
            })?;
        if document.expression.trim().is_empty() {
            return Err(PolicyRuleParseError::EmptyExpression {
                configmap: configmap.to_owned(),
                rule: key.clone(),
            });
        }
        if let Some(pattern) = invalid_match_kinds(&document.match_kinds) {
            return Err(PolicyRuleParseError::InvalidMatchKind {
                configmap: configmap.to_owned(),
                rule: key.clone(),
                pattern,
            });
        }
        rules.push(PolicyRule {
            name: key.clone(),
            enforcement: document.enforcement,
            engine: document.engine.unwrap_or_default(),
            // An unmatchable pattern refused the whole entry above, so nothing is left to record.
            invalid_match_kind: None,
            match_kinds: normalize_match_kinds(document.match_kinds),
            expression: document.expression,
            message: document.message,
        });
    }
    Ok(rules)
}

/// One violation of one rule on one resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyViolation {
    /// The rule that rejected the resource.
    pub rule: String,
    /// `Enforce` or `Warn`.
    pub enforcement: PolicyEnforcement,
    /// Version-agnostic GKNN of the rejected resource, or `"*"` when the failure concerns the
    /// whole bundle (a compile error, a budget overflow).
    pub resource_key: String,
    /// Operator-facing, `Secret`-scrubbed, length-bounded explanation.
    pub message: String,
}

impl PolicyViolation {
    /// Whether this violation blocks the sync.
    #[must_use]
    pub fn is_blocking(&self) -> bool {
        self.enforcement.is_blocking()
    }
}

/// One rule that could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyCompileError {
    /// The rule name.
    pub rule: String,
    /// Value-free diagnostic (a CEL error never quotes an operand).
    pub message: String,
}

/// The verdict of one gate evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyGateOutcome {
    /// Every retained violation, in rule-then-resource order (bounded by
    /// [`MAX_POLICY_VIOLATIONS`]).
    ///
    /// **Blocking findings are never dropped while an advisory can be evicted instead**: see
    /// [`PolicyGate::push_violation`]. A blocking violation can only be lost once every retained
    /// entry is itself blocking, and then [`Self::blocking_truncated`] records it.
    pub violations: Vec<PolicyViolation>,
    /// Every rule that failed to compile (each also produces a blocking violation).
    pub compile_errors: Vec<PolicyCompileError>,
    /// How many `(rule, resource)` pairs were evaluated.
    pub evaluated: usize,
    /// How many rules were in force (after capping).
    pub rules: usize,
    /// How many deterministic CEL steps the evaluation spent.
    pub steps: u64,
    /// Whether an **advisory** violation was dropped at [`MAX_POLICY_VIOLATIONS`].
    ///
    /// Advisories are the only thing truncation may cost: they are best-effort, and the blocking
    /// verdict is what decides the sync.
    pub truncated: bool,
    /// Whether a **blocking** violation was dropped at [`MAX_POLICY_VIOLATIONS`].
    ///
    /// This happens only when every retained entry is itself blocking, and it is never allowed to
    /// be invisible: [`Self::allowed`] is `false` whenever it is set, [`Self::summary`] says so, and
    /// [`Self::blocking_count`] counts the dropped finding. Without it, a full advisory list could
    /// push an `Enforce` violation (or a compile error) off the end and the controller would apply
    /// and prune a bundle the policy refused.
    pub blocking_truncated: bool,
    /// How many **advisory** violations the pass found but did not list.
    ///
    /// [`Self::truncated`] says whether anything was dropped; this says how much. It exists so the
    /// `PolicyAdvisory` condition can report an accurate total instead of presenting a truncated
    /// list as the whole story — an operator who sees "3 advisories" must not have to guess whether
    /// three is the count or the page size.
    pub advisories_omitted: usize,
}

impl PolicyGateOutcome {
    /// Whether the bundle may be applied: no violation blocks it.
    ///
    /// `false` when a blocking violation was *dropped* as well — a truncated verdict is a refusal,
    /// never an allow.
    #[must_use]
    pub fn allowed(&self) -> bool {
        !self.blocking_truncated && !self.violations.iter().any(PolicyViolation::is_blocking)
    }

    /// The retained blocking violations.
    ///
    /// Non-empty whenever [`Self::allowed`] is `false`, because a blocking finding is only ever
    /// dropped once the list is full of blocking findings — and
    /// [`Self::blocking_count`] is the count that includes that last, dropped one.
    pub fn blocking(&self) -> impl Iterator<Item = &PolicyViolation> {
        self.violations.iter().filter(|v| v.is_blocking())
    }

    /// How many blocking violations the pass found, including a dropped one.
    #[must_use]
    pub fn blocking_count(&self) -> usize {
        self.blocking().count() + usize::from(self.blocking_truncated)
    }

    /// The advisory violations (`enforcement: Warn`).
    pub fn advisories(&self) -> impl Iterator<Item = &PolicyViolation> {
        self.violations
            .iter()
            .filter(|v| v.enforcement == PolicyEnforcement::Warn)
    }

    /// A one-line, `Secret`-free summary for `Application.status`.
    #[must_use]
    pub fn summary(&self) -> String {
        let blocking = self.blocking_count();
        let advisory = self.advisory_count();
        let mut summary = format!(
            "policy gate: {blocking} blocking, {advisory} advisory violation(s) across {} rule(s) \
             and {} evaluation(s)",
            self.rules, self.evaluated
        );
        if self.blocking_truncated {
            summary.push_str(
                " (the violation list is full: at least one blocking violation is not listed \
                 above)",
            );
        } else if self.truncated {
            summary.push_str(" (some advisory violations are not listed)");
        }
        summary
    }

    /// How many advisory violations the pass found, **including** the ones it could not list.
    #[must_use]
    pub fn advisory_count(&self) -> usize {
        self.advisories().count() + self.advisories_omitted
    }

    /// The `PolicyAdvisory` condition for this pass.
    ///
    /// Always returned — `True` with the advisories, `False` when there are none — so a stale
    /// advisory from an earlier pass is cleared instead of lingering forever.
    #[must_use]
    pub fn advisories_condition(
        &self,
        generation: Option<i64>,
        timestamp: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time,
    ) -> Condition {
        policy_advisory_condition(
            &self.violations,
            self.rules,
            self.advisories_omitted,
            generation,
            timestamp,
        )
    }
}

/// Builds the `PolicyAdvisory` condition from a set of violations.
///
/// Shared by the two paths that write it: a pass that completed ([`PolicyGateOutcome`]) and a pass
/// the gate **refused** (which never reaches the completion path, so it must build the condition
/// from the violations the refusal carried — a stale `PolicyAdvisory=True` may not outlive the
/// violation that produced it, and the advisories of a refused bundle are exactly what an operator
/// needs to see).
///
/// `omitted` is the number of advisories the violation budget dropped
/// ([`PolicyGateOutcome::advisories_omitted`]): the message reports the **total** found, so a
/// truncated list never reads like a complete one. At most [`MAX_CONDITION_ADVISORIES`] entries are
/// spelled out — the condition shares `Application.status`'s budget with everything else on the
/// object (trap T9), so it is capped **before** the string is built rather than truncated after.
#[must_use]
pub fn policy_advisory_condition(
    violations: &[PolicyViolation],
    rules: usize,
    omitted: usize,
    generation: Option<i64>,
    timestamp: k8s_openapi::apimachinery::pkg::apis::meta::v1::Time,
) -> Condition {
    let retained = violations
        .iter()
        .filter(|violation| violation.enforcement == PolicyEnforcement::Warn);
    let total = retained.clone().count() + omitted;
    if total == 0 {
        return Condition::new(
            CONDITION_POLICY_ADVISORY,
            ConditionStatus::False,
            REASON_POLICY_COMPLIANT,
            format!("no policy advisories ({rules} rule(s) in force)"),
            timestamp,
        )
        .with_observed_generation(generation);
    }
    let listed: Vec<String> = retained
        .take(MAX_CONDITION_ADVISORIES)
        .map(|violation| format!("{}: {}", violation.rule, violation.message))
        .collect();
    let unlisted = total.saturating_sub(listed.len());
    let message = if listed.is_empty() {
        format!("{unlisted} advisory policy violation(s) are not listed here")
    } else {
        let mut message = listed.join("; ");
        if unlisted > 0 {
            message.push_str(&format!(" (+{unlisted} more)"));
        }
        message
    };
    Condition::new(
        CONDITION_POLICY_ADVISORY,
        ConditionStatus::True,
        REASON_POLICY_ADVISORY,
        bounded(message, MAX_POLICY_MESSAGE_CHARS),
        timestamp,
    )
    .with_observed_generation(generation)
}

/// The inputs of one gate evaluation. Everything the gate needs is injected.
pub struct PolicyGateInput<'a> {
    /// The `Application` being synced (used for the `app` root variable and messages).
    pub app: &'a Application,
    /// The rules in force for this `Application` (project + `ConfigMap`).
    pub rules: &'a [PolicyRule],
    /// The rendered bundle, **after** Stage-2 scope normalization.
    pub resources: &'a [DesiredResource],
}

impl std::fmt::Debug for PolicyGateInput<'_> {
    /// Deliberately omits the resources: a bundle may hold a `Secret` body.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyGateInput")
            .field("application", &self.app.name_any())
            .field("rules", &self.rules.len())
            .field("resources", &self.resources.len())
            .finish()
    }
}

/// Every bound the gate enforces.
///
/// # How a host overrides them
///
/// The defaults are the documented production bounds. A host installs different ones with
/// [`PolicyGate::with_config`]; the controller's own seam is
/// `InventorySyncPipeline::with_policy_gate`, so a smaller cluster (or a test) can narrow
/// [`Self::max_rules`] / [`Self::max_resources`] without touching the engine, and an operator who
/// needs a wider rule set raises them there deliberately:
///
/// ```ignore
/// let gate = PolicyGate::with_config(PolicyGateConfig::default().with_max_rules(8));
/// let pipeline = pipeline.with_policy_gate(gate);
/// ```
///
/// Every field is a **fail-closed** bound: crossing it produces a blocking `<rule-budget>`,
/// `<resource-budget>`, `<node-budget>` or `<step-budget>` violation, never a silent skip and never
/// a narrowed evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyGateConfig {
    /// Per-expression CEL budget.
    pub cel: CelBudget,
    /// Total CEL steps **one pass** may spend (every rule × every resource).
    ///
    /// Unlike [`Self::cel`], which bounds a single expression evaluation, this is the pass-level
    /// ceiling: it is what makes the gate's work proportional to the bundle rather than to
    /// `rules × resources` (see [`Self`] and [`PolicyGate::evaluate`]).
    pub total_steps: u64,
    /// Maximum rules in force ([`MAX_POLICY_RULES`]).
    pub max_rules: usize,
    /// Maximum resources evaluated ([`MAX_POLICY_RESOURCES`]).
    pub max_resources: usize,
    /// Maximum reported violations ([`MAX_POLICY_VIOLATIONS`]).
    pub max_violations: usize,
    /// Maximum message length ([`MAX_POLICY_MESSAGE_CHARS`]).
    pub max_message_chars: usize,
    /// Maximum cached programs ([`MAX_CACHED_PROGRAMS`]).
    pub max_cached_programs: usize,
}

impl Default for PolicyGateConfig {
    fn default() -> Self {
        Self {
            cel: CelBudget::default(),
            total_steps: DEFAULT_TOTAL_STEPS,
            max_rules: MAX_POLICY_RULES,
            max_resources: MAX_POLICY_RESOURCES,
            max_violations: MAX_POLICY_VIOLATIONS,
            max_message_chars: MAX_POLICY_MESSAGE_CHARS,
            max_cached_programs: MAX_CACHED_PROGRAMS,
        }
    }
}

impl PolicyGateConfig {
    /// Returns this configuration with a different total step budget (tests, small clusters).
    #[must_use]
    pub fn with_total_steps(mut self, steps: u64) -> Self {
        self.total_steps = steps;
        self
    }

    /// Returns this configuration with a different per-expression budget.
    #[must_use]
    pub fn with_cel_budget(mut self, budget: CelBudget) -> Self {
        self.cel = budget;
        self
    }

    /// Returns this configuration with a different rule bound.
    ///
    /// Raising it above [`MAX_POLICY_RULES`] is a deliberate capacity decision (each rule is one
    /// more program and one more pass over the bundle); lowering it refuses a rule set sooner.
    /// Either way the gate refuses rather than narrowing — see [`Self`].
    #[must_use]
    pub fn with_max_rules(mut self, rules: usize) -> Self {
        self.max_rules = rules;
        self
    }

    /// Returns this configuration with a different resource bound.
    #[must_use]
    pub fn with_max_resources(mut self, resources: usize) -> Self {
        self.max_resources = resources;
        self
    }

    /// Returns this configuration with a different reported-violation bound.
    #[must_use]
    pub fn with_max_violations(mut self, violations: usize) -> Self {
        self.max_violations = violations;
        self
    }

    /// Returns this configuration with a different message length bound.
    #[must_use]
    pub fn with_max_message_chars(mut self, chars: usize) -> Self {
        self.max_message_chars = chars;
        self
    }
}

/// An injected OPA/Rego evaluator (`opa-policy`).
///
/// The gate itself does not depend on a Rego crate: `T17.5` governs which crates may enter the
/// build, and an evaluator that can reach the network or the filesystem would reopen exactly the
/// SSRF and exfiltration vectors this gate exists to close. The embedded `regorus` engine behind the
/// feature (module `rego`, compiled only with `--features opa-policy`) is the audited implementation
/// that ships; a host may wire any other one.
///
/// Every error it returns is a blocking violation, and the two roots are passed **separately** and
/// by reference so the gate never deep-clones a rendered document per `(rule, resource)`.
pub trait RegoEvaluator: Send + Sync + std::fmt::Debug {
    /// Evaluates `policy` at `entrypoint` against the `app` facts and the (redacted) `object`
    /// document, answering `true` when the resource complies.
    ///
    /// `pass` is this pass's budget ([`Self::begin_pass`]): charge it for the work performed, and
    /// refuse once it is gone.
    ///
    /// # Errors
    ///
    /// Any failure; the gate fails closed.
    fn evaluate(
        &self,
        pass: &RegoPassBudget,
        policy: &str,
        entrypoint: &str,
        app: &Value,
        object: &Value,
    ) -> Result<bool, String>;

    /// Announces the start of one gate pass and returns **that pass's** budget.
    ///
    /// A Rego interpreter has no fuel counter, only a wall-clock limit, so an engine has to bound
    /// its work per pass itself — otherwise a bundle could spend `rules × resources ×
    /// per-evaluation-limit`. The allowance is *returned*, not stored: the pass owns it, so two
    /// `Application`s reconciling at the same time each get their own, and neither can reset the
    /// other's by starting (the previous design kept one process-global counter here, which a
    /// concurrent `begin_pass` reset — the fail-open that made a started pass appear to have spent
    /// nothing — or drained, the spurious refusal).
    ///
    /// A budget nobody can exhaust is [`RegoPassBudget::unlimited`], which is the safe default for
    /// an evaluator that enforces its own bound per evaluation.
    fn begin_pass(&self) -> RegoPassBudget {
        RegoPassBudget::unlimited()
    }
}

/// The evaluation budget of **one** gate pass.
///
/// Created by [`RegoEvaluator::begin_pass`] and dropped with the pass (see
/// [`PolicyGate::evaluate`]), so it cannot be shared, reset, or observed by another pass. The
/// counter is atomic only because the trait hands it out behind a shared reference; a pass is
/// single-threaded, and charges are saturating additions.
#[derive(Debug)]
pub struct RegoPassBudget {
    /// The allowance, or `None` for "unlimited" (an engine that bounds each evaluation itself).
    limit: Option<Duration>,
    spent_nanos: AtomicU64,
}

impl RegoPassBudget {
    /// A budget of `limit` wall-clock time for one pass.
    #[must_use]
    pub fn new(limit: Duration) -> Self {
        Self {
            limit: Some(limit),
            spent_nanos: AtomicU64::new(0),
        }
    }

    /// A budget that never refuses.
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            limit: None,
            spent_nanos: AtomicU64::new(0),
        }
    }

    /// The allowance, if this budget has one.
    #[must_use]
    pub fn limit(&self) -> Option<Duration> {
        self.limit
    }

    /// How much of the allowance has been charged so far.
    #[must_use]
    pub fn spent(&self) -> Duration {
        Duration::from_nanos(self.spent_nanos.load(Ordering::Relaxed))
    }

    /// Returns the time left, or `None` when the budget is unlimited.
    #[must_use]
    pub fn remaining(&self) -> Option<Duration> {
        self.limit.map(|limit| limit.saturating_sub(self.spent()))
    }

    /// Returns whether more work may be started, and the message to refuse with when not.
    ///
    /// # Errors
    ///
    /// A refusal message once the allowance is spent. It names the allowance, never the policy.
    pub fn check(&self) -> Result<(), String> {
        let Some(limit) = self.limit else {
            return Ok(());
        };
        if self.spent() >= limit {
            return Err(format!(
                "the Rego evaluation budget of {} ms for this sync is exhausted; refusing the \
                 bundle rather than evaluating only part of it",
                limit.as_millis()
            ));
        }
        Ok(())
    }

    /// Charges `elapsed` against the allowance (saturating).
    pub fn charge(&self, elapsed: Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let _ = self
            .spent_nanos
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |spent| {
                Some(spent.saturating_add(nanos))
            });
    }
}

/// Evaluates policy rules over a rendered bundle. Pure, deterministic, and bounded.
#[derive(Debug)]
pub struct PolicyGate {
    config: PolicyGateConfig,
    programs: DashMap<String, CachedProgram>,
    /// Optional OPA/Rego evaluator. `None` means a `Rego` rule fails closed.
    rego: Option<Arc<dyn RegoEvaluator>>,
}

#[derive(Debug, Clone)]
enum CachedProgram {
    Compiled(Arc<Program>),
    Failed(Arc<CelError>),
}

impl Default for PolicyGate {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyGate {
    /// Builds a gate with the default bounds and an empty program cache.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(PolicyGateConfig::default())
    }

    /// Builds a gate with explicit bounds.
    #[must_use]
    pub fn with_config(config: PolicyGateConfig) -> Self {
        Self {
            config,
            programs: DashMap::new(),
            rego: None,
        }
    }

    /// Wires an OPA/Rego evaluator (`opa-policy`).
    ///
    /// Without the feature no host can wire one, so a `Rego` rule is always a compile error (fail
    /// closed) in a default build. The crate itself is deliberately **not** linked here: `T17.5`
    /// governs which crates may enter the build, and the audit for a Rego engine is a separate
    /// deliverable — this method is the integration point it plugs into.
    #[cfg(feature = "opa-policy")]
    #[must_use]
    pub fn with_rego(mut self, evaluator: Arc<dyn RegoEvaluator>) -> Self {
        self.rego = Some(evaluator);
        self
    }

    /// The bounds this gate enforces.
    #[must_use]
    pub fn config(&self) -> &PolicyGateConfig {
        &self.config
    }

    /// How many programs the cache holds.
    #[must_use]
    pub fn cached_programs(&self) -> usize {
        self.programs.len()
    }

    /// Evaluates `input` and returns the verdict.
    ///
    /// This is a pure function: the same input always produces the same output, and it performs no
    /// I/O of any kind.
    #[must_use]
    pub fn evaluate(&self, input: &PolicyGateInput<'_>) -> PolicyGateOutcome {
        let mut outcome = PolicyGateOutcome::default();
        if input.rules.is_empty() {
            return outcome;
        }

        // Bound the rule list. Dropping rules would be a bypass, so an over-long list fails closed.
        let rules = if input.rules.len() > self.config.max_rules {
            let message = format!(
                "{} policy rule(s) are in force, over the {}-rule limit; narrow the project's \
                 policyRules or the policies ConfigMap",
                input.rules.len(),
                self.config.max_rules
            );
            self.push_violation(
                &mut outcome,
                &PolicyViolation {
                    rule: "<rule-budget>".to_owned(),
                    enforcement: PolicyEnforcement::Enforce,
                    resource_key: "*".to_owned(),
                    message: self.bounded(message),
                },
            );
            &input.rules[..self.config.max_rules]
        } else {
            input.rules
        };
        // Bound the bundle the same way: skipping resources would let a large bundle bypass policy.
        let resources = if input.resources.len() > self.config.max_resources {
            let message = format!(
                "the rendered bundle holds {} resource(s), over the {}-resource policy limit",
                input.resources.len(),
                self.config.max_resources
            );
            self.push_violation(
                &mut outcome,
                &PolicyViolation {
                    rule: "<resource-budget>".to_owned(),
                    enforcement: PolicyEnforcement::Enforce,
                    resource_key: "*".to_owned(),
                    message: self.bounded(message),
                },
            );
            &input.resources[..self.config.max_resources]
        } else {
            input.resources
        };
        outcome.rules = rules.len();

        // Redact every resource exactly once, and remember the payloads so messages can be
        // scrubbed before they leave the gate. A document over the node budget is refused here,
        // before any rule sees it: an oversized body would make every evaluation's cost
        // unbounded, and "cannot evaluate" must never read as "compliant".
        let mut views = Vec::with_capacity(resources.len());
        let mut secrets = Vec::new();
        for resource in resources {
            let view = policy_view(resource, &mut secrets);
            if let Err(err) = cel::check_json_bounds(&view, &self.config.cel) {
                let message = format!(
                    "the rendered resource is too large to evaluate under the policy budget \
                     ({err}); refusing it rather than skipping it"
                );
                self.push_violation(
                    &mut outcome,
                    &PolicyViolation {
                        rule: "<node-budget>".to_owned(),
                        enforcement: PolicyEnforcement::Enforce,
                        resource_key: resource.key.canonical(),
                        message: self.bounded(redact_secret_values(&message, &secrets)),
                    },
                );
                views.push(None);
                continue;
            }
            views.push(Some(view));
        }
        // The `app` facts are built once and borrowed by both engines: nothing below clones a
        // resource document per `(rule, resource)` any more (`T20.2`, finding M3).
        let app_root = app_facts(input.app);
        let mut roots_base = BTreeMap::new();
        roots_base.insert(cel::APP_ROOT.to_owned(), app_root.clone());
        // One budget for this pass, owned by this call and dropped with it (`T20.2`, finding H2):
        // two `Application`s reconciling at the same time each get their own allowance, so neither
        // can reset or drain the other's.
        let rego_pass = self.rego.as_ref().map(|rego| rego.begin_pass());

        let mut steps: u64 = 0;
        'rules: for rule in rules {
            // A rule that can never match a resource allows everything, which is the bypass this
            // gate exists to prevent — so an unmatchable `matchKinds` entry blocks instead of
            // silently applying to nothing (a `v1`/`apps/v1` typo is the natural way to write it).
            if let Some(pattern) = &rule.invalid_match_kind {
                let message = format!(
                    "the rule's matchKinds entry {pattern:?} names an apiVersion, not a Kind, so \
                     the rule would match no resource and allow everything; write `Kind`, \
                     `group/Kind`, `group/*`, or `*`"
                );
                outcome.compile_errors.push(PolicyCompileError {
                    rule: rule.name.clone(),
                    message: message.clone(),
                });
                let violation =
                    self.violation(rule, PolicyEnforcement::Enforce, "*", &message, &secrets);
                self.push_violation(&mut outcome, &violation);
                continue 'rules;
            }
            // Compile one rule. `None` means "no CEL program to run" (a `Rego` rule, evaluated per
            // resource through the injected evaluator).
            let program: Option<Arc<Program>> = match rule.engine {
                PolicyRuleEngine::Cel => match self.compile(&rule.expression) {
                    Ok(program) => Some(program),
                    Err(err) => {
                        outcome.compile_errors.push(PolicyCompileError {
                            rule: rule.name.clone(),
                            message: err.to_string(),
                        });
                        let violation = self.violation(
                            rule,
                            PolicyEnforcement::Enforce,
                            "*",
                            &format!("the rule does not compile, so it fails closed: {err}"),
                            &secrets,
                        );
                        self.push_violation(&mut outcome, &violation);
                        continue 'rules;
                    }
                },
                PolicyRuleEngine::Rego => {
                    if self.rego.is_none() {
                        let message = "policy engine `Rego` is not available in this controller \
                                       build (build it with the `opa-policy` feature and wire a \
                                       Rego evaluator); the rule is refused rather than skipped";
                        outcome.compile_errors.push(PolicyCompileError {
                            rule: rule.name.clone(),
                            message: message.to_owned(),
                        });
                        let violation = self.violation(
                            rule,
                            PolicyEnforcement::Enforce,
                            "*",
                            message,
                            &secrets,
                        );
                        self.push_violation(&mut outcome, &violation);
                        continue 'rules;
                    }
                    None
                }
            };

            for (resource, view) in resources.iter().zip(views.iter()) {
                if !rule.matches_kind(&resource.gvk.group, &resource.gvk.kind) {
                    continue;
                }
                // A resource the gate already refused (over the node budget) is not evaluated: the
                // refusal is recorded, and pretending it passed would be the fail-open this gate
                // exists to prevent.
                let Some(view) = view else {
                    continue;
                };
                let key = resource.key.canonical();
                outcome.evaluated += 1;

                let verdict: Result<bool, String> = match rule.engine {
                    PolicyRuleEngine::Cel => match program.as_ref() {
                        Some(program) => {
                            // The document is *borrowed*, never cloned: one pass, one copy.
                            match program.evaluate_counting_with(&roots_base, Some(view)) {
                                Ok((Value::Bool(verdict), used)) => {
                                    steps = steps.saturating_add(used);
                                    Ok(verdict)
                                }
                                Ok((other, used)) => {
                                    steps = steps.saturating_add(used);
                                    Err(format!(
                                        "the expression must evaluate to a boolean, found {}",
                                        json_kind(&other)
                                    ))
                                }
                                Err(failure) => {
                                    // Charge what the failure really spent (finding M1): an
                                    // always-erroring rule must not escape the pass budget.
                                    steps = steps.saturating_add(failure.steps);
                                    Err(format!(
                                        "the expression could not be evaluated: {}",
                                        failure.error
                                    ))
                                }
                            }
                        }
                        // A `Cel` rule always carries a program; refusing beats skipping.
                        None => Err("the rule was not compiled".to_owned()),
                    },
                    PolicyRuleEngine::Rego => match (&self.rego, &rego_pass) {
                        (Some(rego), Some(pass)) => rego
                            .evaluate(pass, &rule.expression, rule.name.as_str(), &app_root, view)
                            .map_err(|err| format!("the Rego policy failed: {err}")),
                        _ => Err("no Rego evaluator is wired".to_owned()),
                    },
                };

                match verdict {
                    Ok(true) => {}
                    Ok(false) => {
                        let violation = self.violation(
                            rule,
                            rule.enforcement,
                            &key,
                            rule.message
                                .as_deref()
                                .unwrap_or("the rendered resource violates this invariant"),
                            &secrets,
                        );
                        self.push_violation(&mut outcome, &violation);
                    }
                    Err(message) => {
                        // Fail closed: whatever went wrong, the bundle is not proven compliant.
                        let violation = self.violation(
                            rule,
                            PolicyEnforcement::Enforce,
                            &key,
                            &message,
                            &secrets,
                        );
                        self.push_violation(&mut outcome, &violation);
                    }
                }

                if steps > self.config.total_steps {
                    // Deterministic timeout for the whole pass: stop and refuse, never continue
                    // with a partially evaluated bundle.
                    let message = format!(
                        "the policy evaluation budget of {} step(s) is exhausted; refusing the \
                         sync rather than evaluating only part of the bundle",
                        self.config.total_steps
                    );
                    self.push_violation(
                        &mut outcome,
                        &PolicyViolation {
                            rule: "<step-budget>".to_owned(),
                            enforcement: PolicyEnforcement::Enforce,
                            resource_key: "*".to_owned(),
                            message: self.bounded(message),
                        },
                    );
                    break 'rules;
                }
            }
        }

        outcome.steps = steps;
        outcome
    }

    /// Truncates a message to this gate's configured bound
    /// ([`PolicyGateConfig::max_message_chars`]).
    ///
    /// One implementation for every message the gate emits (the policy violation, the budget
    /// findings and the rule diagnostics), so a host that narrows or widens the bound sees it
    /// applied everywhere.
    fn bounded(&self, message: impl Into<String>) -> String {
        bounded(message, self.config.max_message_chars)
    }

    /// Compiles (or fetches from the bounded cache) one CEL expression.
    fn compile(&self, expression: &str) -> Result<Arc<Program>, Arc<CelError>> {
        if let Some(cached) = self.programs.get(expression) {
            return match cached.value() {
                CachedProgram::Compiled(program) => Ok(program.clone()),
                CachedProgram::Failed(err) => Err(err.clone()),
            };
        }
        let compiled = match cel::compile_with(expression, self.config.cel) {
            Ok(program) => CachedProgram::Compiled(Arc::new(program)),
            Err(err) => CachedProgram::Failed(Arc::new(err)),
        };
        let answer = match &compiled {
            CachedProgram::Compiled(program) => Ok(program.clone()),
            CachedProgram::Failed(err) => Err(err.clone()),
        };
        // A bounded cache: past the cap the expression is still compiled, just not retained.
        if self.programs.len() < self.config.max_cached_programs {
            self.programs.insert(expression.to_owned(), compiled);
        }
        answer
    }

    fn violation(
        &self,
        rule: &PolicyRule,
        enforcement: PolicyEnforcement,
        resource_key: &str,
        message: &str,
        secrets: &[String],
    ) -> PolicyViolation {
        let scrubbed = redact_secret_values(message, secrets);
        PolicyViolation {
            rule: rule.name.clone(),
            enforcement,
            resource_key: resource_key.to_owned(),
            message: self.bounded(format!("{scrubbed} (policy {:?})", rule.name)),
        }
    }

    /// Records one violation, **never** at the cost of a blocking finding.
    ///
    /// `Application.status` is bounded (trap T9), so the list is bounded too — but truncation must
    /// not be able to change the verdict. An advisory is therefore the only finding it may cost:
    ///
    /// * free slot → append;
    /// * full and the new finding is an advisory → drop it, set [`PolicyGateOutcome::truncated`];
    /// * full and the new finding is **blocking** → evict the last retained advisory and keep the
    ///   blocker;
    /// * full and *every* retained finding is blocking → set
    ///   [`PolicyGateOutcome::blocking_truncated`], which keeps [`PolicyGateOutcome::allowed`] at
    ///   `false` and makes [`PolicyGateOutcome::summary`] say a blocking violation is unlisted.
    ///
    /// That invariant is what the finding C1 fix rests on: a full advisory list can no longer hide
    /// the `Enforce` violation (or the compile error, rule-budget, node-budget and step-budget
    /// findings, which are all blocking) that decides whether the controller applies and prunes.
    fn push_violation(&self, outcome: &mut PolicyGateOutcome, violation: &PolicyViolation) {
        if outcome.violations.len() < self.config.max_violations {
            outcome.violations.push(violation.clone());
            return;
        }
        if !violation.is_blocking() {
            outcome.truncated = true;
            outcome.advisories_omitted += 1;
            return;
        }
        match outcome
            .violations
            .iter()
            .rposition(|kept| !kept.is_blocking())
        {
            Some(index) => {
                // Blocking findings are ordered before the advisories they displace, so the list
                // stays "blocking first, then advisories" however it is filled.
                outcome.violations.remove(index);
                outcome.violations.push(violation.clone());
                outcome.truncated = true;
                // The evicted entry is an advisory the pass found but can no longer list, so the
                // condition's count has to include it.
                outcome.advisories_omitted += 1;
            }
            None => outcome.blocking_truncated = true,
        }
    }
}

/// Truncates a message to `limit` characters on a char boundary.
///
/// Every message the gate emits goes through this with the **configured** limit
/// (`PolicyGateConfig::max_message_chars`), never with a second hard-coded one: a violation reaches
/// `Application.status`, whose budget is shared by the whole object (trap T9), and a host that
/// narrows or widens the bound must see it applied everywhere.
fn bounded(message: impl Into<String>, limit: usize) -> String {
    let message = message.into();
    if message.chars().count() <= limit {
        return message;
    }
    let mut truncated: String = message.chars().take(limit).collect();
    truncated.push('…');
    truncated
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_i64() => "int",
        Value::Number(_) => "double",
        Value::String(_) => "string",
        Value::Array(_) => "list",
        Value::Object(_) => "map",
    }
}

/// Builds the `app` root variable: the `Application` facts a policy may reason about.
///
/// Returned as a plain [`Value`] so it can be handed to a CEL root map *and* to a Rego evaluator
/// without being rebuilt (or re-cloned) per rule.
fn app_facts(app: &Application) -> Value {
    serde_json::json!({
        "name": app.name_any(),
        "namespace": app.namespace().unwrap_or_else(|| CONTROL_PLANE_NAMESPACE.to_owned()),
        "project": app.spec.project,
        "destination": {
            "cluster": app.spec.destination.cluster,
            "namespace": app.spec.destination.namespace,
        },
    })
}

/// The redacted view of one resource plus the payloads a message must never quote.
///
/// Only a `v1/Secret` is touched: its `data`/`stringData` **values** become
/// [`REDACTED_SECRET_VALUE`], so a policy still sees the keys, the `type`, and the metadata.
fn policy_view(resource: &DesiredResource, secrets: &mut Vec<String>) -> Value {
    // A `DynamicObject` always serializes. If it somehow did not, `null` is the safe view: every
    // field selection on it errors, and an error fails closed instead of silently allowing.
    let mut value = serde_json::to_value(&resource.object).unwrap_or(Value::Null);
    let is_secret = resource.gvk.group.is_empty() && resource.gvk.kind == "Secret";
    if !is_secret {
        return value;
    }
    if let Value::Object(map) = &mut value {
        for field in ["data", "stringData"] {
            let Some(Value::Object(entries)) = map.get_mut(field) else {
                continue;
            };
            for entry in entries.values_mut() {
                if let Value::String(payload) = entry {
                    collect_secret(secrets, payload);
                }
                *entry = Value::String(REDACTED_SECRET_VALUE.to_owned());
            }
        }
    }
    value
}

/// Records every form of a `Secret` payload a message could echo.
///
/// Key *names* are deliberately not recorded: they are visible to a policy on purpose, and scrubbing
/// them would mangle diagnostics ("no field \"password\" on object").
///
/// # The `< 4`-byte caveat
///
/// A payload shorter than [`MIN_SECRET_LEN`] bytes is **not** recorded, so a message an operator
/// writes that quotes a 1–3 byte payload is not scrubbed. That is a deliberate trade-off, not an
/// oversight: a two-character needle occurs by chance in ordinary prose, so scrubbing it would
/// corrupt unrelated diagnostics (which is itself a way to make a policy's output unreadable), and
/// such a payload carries almost no secret material. What protects the value in every case is the
/// first line of defense — the evaluator never sees it, because the view replaces every
/// `data`/`stringData` value with [`REDACTED_SECRET_VALUE`] *before* evaluation — so the only way a
/// short payload can appear in a message is an operator template that already contained it.
const MIN_SECRET_LEN: usize = 4;

fn collect_secret(secrets: &mut Vec<String>, payload: &str) {
    if payload.len() >= MIN_SECRET_LEN {
        secrets.push(payload.to_owned());
    }
    if let Ok(decoded) = STANDARD.decode(payload)
        && let Ok(text) = String::from_utf8(decoded)
        && text.len() >= MIN_SECRET_LEN
    {
        secrets.push(text);
    }
}

/// Replaces every `Secret` payload a message quotes with [`REDACTED_SECRET_VALUE`].
///
/// This is the trap guard's second line of defense: the evaluator already receives a redacted
/// document, and this scrubs the one string that leaves the gate anyway (a violation message, which
/// may be assembled from an operator-supplied template or a CEL diagnostic).
#[must_use]
pub fn redact_secret_values(message: &str, secrets: &[String]) -> String {
    let mut scrubbed = message.to_owned();
    for secret in secrets {
        if secret.len() < MIN_SECRET_LEN || !scrubbed.contains(secret.as_str()) {
            continue;
        }
        scrubbed = scrubbed.replace(secret.as_str(), REDACTED_SECRET_VALUE);
    }
    scrubbed
}

#[cfg(test)]
mod tests {
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
    use k8s_openapi::jiff::Timestamp;
    use serde_json::json;

    use super::*;
    use crate::manifest::{GroupVersionKind, ResourceKey};

    const APPLICATION: &str = r#"
apiVersion: ferriscd.io/v1alpha1
kind: Application
metadata:
  name: payments-api
  namespace: ferriscd-system
spec:
  project: payments
  source:
    git:
      repoURL: https://github.com/example/payments.git
  destination:
    cluster: in-cluster
    namespace: payments
"#;

    fn application() -> Application {
        serde_saphyr::from_str(APPLICATION).expect("test application must parse")
    }

    /// Documents the intent of a test rule set (`Vec<PolicyRule>`), nothing more.
    fn rule_set(rules: Vec<PolicyRule>) -> Vec<PolicyRule> {
        rules
    }

    fn desired(api_version: &str, kind: &str, name: &str, body: Value) -> DesiredResource {
        let gvk = GroupVersionKind::parse(api_version, kind).expect("test apiVersion");
        let mut document =
            json!({ "apiVersion": api_version, "kind": kind, "metadata": { "name": name } });
        if let Value::Object(extra) = body {
            let object = document
                .as_object_mut()
                .expect("the fixture document is an object");
            for (key, value) in extra {
                object.insert(key, value);
            }
        }
        let object = serde_json::from_value(document).expect("test object");
        let key = ResourceKey::new(
            gvk.group.clone(),
            gvk.kind.clone(),
            Some("payments".to_owned()),
            name,
        );
        DesiredResource {
            key,
            gvk,
            object,
            source_file: "manifests/app.yaml".to_owned(),
        }
    }

    fn deployment(name: &str, privileged: bool, image: &str) -> DesiredResource {
        desired(
            "apps/v1",
            "Deployment",
            name,
            json!({
                "metadata": {
                    "name": name,
                    "namespace": "payments",
                    "labels": { "cost-center": "cc-42" }
                },
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [{
                                "name": "app",
                                "image": image,
                                "securityContext": { "privileged": privileged }
                            }]
                        }
                    }
                }
            }),
        )
    }

    fn secret(name: &str, key: &str, plaintext: &str) -> DesiredResource {
        desired(
            "v1",
            "Secret",
            name,
            json!({
                "metadata": { "name": name, "namespace": "payments" },
                "type": "Opaque",
                "data": { key: STANDARD.encode(plaintext) },
                "stringData": { "string-token": plaintext }
            }),
        )
    }

    const NO_PRIVILEGED: &str = "!object.spec.template.spec.containers.exists(c, \
                                 has(c.securityContext) && c.securityContext.privileged == true)";

    fn evaluate(
        gate: &PolicyGate,
        rules: &[PolicyRule],
        resources: &[DesiredResource],
    ) -> PolicyGateOutcome {
        let app = application();
        gate.evaluate(&PolicyGateInput {
            app: &app,
            rules,
            resources,
        })
    }

    #[test]
    fn an_enforce_violation_blocks_the_bundle_and_names_the_resource() {
        let gate = PolicyGate::new();
        let rules = rule_set(vec![
            PolicyRule::new("no-privileged", PolicyEnforcement::Enforce, NO_PRIVILEGED)
                .with_match_kinds(vec!["apps/Deployment".to_owned()])
                .with_message("privileged containers are forbidden"),
        ]);
        let resources = [
            deployment("web", false, "ghcr.io/example/app:1"),
            deployment("worker", true, "ghcr.io/example/worker:1"),
        ];

        let outcome = evaluate(&gate, &rules, &resources);
        assert!(
            !outcome.allowed(),
            "a privileged container must block: {outcome:?}"
        );
        assert_eq!(outcome.violations.len(), 1);
        let violation = &outcome.violations[0];
        assert_eq!(violation.rule, "no-privileged");
        assert_eq!(violation.enforcement, PolicyEnforcement::Enforce);
        assert!(violation.is_blocking());
        assert!(
            violation.resource_key.contains("Deployment")
                && violation.resource_key.contains("worker"),
            "the violation must name the offending resource: {violation:?}"
        );
        assert!(
            violation
                .message
                .contains("privileged containers are forbidden"),
            "{violation:?}"
        );
        assert_eq!(outcome.evaluated, 2);

        // A compliant bundle passes the same rule.
        let compliant = evaluate(&gate, &rules, &resources[..1]);
        assert!(compliant.allowed(), "{compliant:?}");
        assert!(compliant.violations.is_empty());
    }

    #[test]
    fn a_warn_violation_allows_the_sync_and_surfaces_an_advisory_condition() {
        let gate = PolicyGate::new();
        let rules = rule_set(vec![
            PolicyRule::new(
                "prefer-approved-registry",
                PolicyEnforcement::Warn,
                "object.spec.template.spec.containers.all(c, c.image.startsWith(\"ghcr.io/example/\"))",
            )
            .with_message("prefer the approved registry"),
        ]);
        let resources = [deployment("web", false, "docker.io/library/nginx:1")];

        let outcome = evaluate(&gate, &rules, &resources);
        assert!(
            outcome.allowed(),
            "a Warn violation must not block: {outcome:?}"
        );
        assert_eq!(outcome.advisories().count(), 1);

        let timestamp = Time(Timestamp::now());
        let condition = outcome.advisories_condition(Some(7), timestamp.clone());
        assert_eq!(condition.type_, CONDITION_POLICY_ADVISORY);
        assert_eq!(condition.status, ConditionStatus::True);
        assert_eq!(condition.reason, REASON_POLICY_ADVISORY);
        assert_eq!(condition.observed_generation, Some(7));
        assert!(
            condition.message.contains("prefer the approved registry"),
            "{condition:?}"
        );

        // The same gate on a compliant bundle reports `False`, so a stale advisory is cleared
        // instead of lingering forever.
        let clean = evaluate(
            &gate,
            &rules,
            &[deployment("web", false, "ghcr.io/example/app:1")],
        );
        assert!(clean.allowed());
        let cleared = clean.advisories_condition(Some(8), timestamp);
        assert_eq!(cleared.status, ConditionStatus::False);
        assert_eq!(cleared.reason, REASON_POLICY_COMPLIANT);
        assert!(
            cleared.message.contains("no policy advisories"),
            "{cleared:?}"
        );
    }

    #[test]
    fn an_invalid_expression_fails_closed_even_when_the_rule_only_warns() {
        // The trap guard: "never fail open when a policy rule fails to compile". A `Warn` rule that
        // cannot be compiled blocks, because silently dropping it would be indistinguishable from
        // the policy never having been written.
        for enforcement in [PolicyEnforcement::Enforce, PolicyEnforcement::Warn] {
            let gate = PolicyGate::new();
            let rules = rule_set(vec![
                PolicyRule::new(
                    "broken",
                    enforcement,
                    "object.spec.template.spec.containers.all(c,",
                )
                .with_message("this expression is truncated"),
            ]);
            let outcome = evaluate(
                &gate,
                &rules,
                &[deployment("web", false, "ghcr.io/example/app:1")],
            );
            assert!(
                !outcome.allowed(),
                "an uncompilable {enforcement:?} rule must fail closed: {outcome:?}"
            );
            assert_eq!(outcome.compile_errors.len(), 1);
            assert_eq!(outcome.compile_errors[0].rule, "broken");
            let violation = &outcome.violations[0];
            assert_eq!(violation.enforcement, PolicyEnforcement::Enforce);
            assert_eq!(violation.resource_key, "*");
            assert!(
                violation.message.contains("does not compile"),
                "{violation:?}"
            );
        }

        // An unsupported builtin is a compile error too, never an implicit allow.
        let gate = PolicyGate::new();
        let rules = rule_set(vec![PolicyRule::new(
            "regex",
            PolicyEnforcement::Warn,
            "object.metadata.name.matches(\"^web$\")",
        )]);
        let outcome = evaluate(
            &gate,
            &rules,
            &[deployment("web", false, "ghcr.io/example/app:1")],
        );
        assert!(!outcome.allowed(), "{outcome:?}");
        assert!(
            outcome.compile_errors[0]
                .message
                .contains("does not support"),
            "{outcome:?}"
        );
    }

    #[test]
    fn an_evaluation_error_or_a_non_boolean_result_fails_closed() {
        let resources = [deployment("web", false, "ghcr.io/example/app:1")];

        // A type error (comparing a map with an int) cannot prove compliance.
        let gate = PolicyGate::new();
        let rules = rule_set(vec![PolicyRule::new(
            "type-error",
            PolicyEnforcement::Warn,
            "object.spec > 3",
        )]);
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(!outcome.allowed(), "{outcome:?}");
        assert_eq!(
            outcome.violations[0].enforcement,
            PolicyEnforcement::Enforce
        );
        assert!(
            outcome.violations[0]
                .message
                .contains("could not be evaluated"),
            "{outcome:?}"
        );

        // A non-boolean result is not an invariant.
        let gate = PolicyGate::new();
        let rules = rule_set(vec![PolicyRule::new(
            "not-a-boolean",
            PolicyEnforcement::Warn,
            "object.metadata.name",
        )]);
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(!outcome.allowed(), "{outcome:?}");
        assert!(
            outcome.violations[0]
                .message
                .contains("must evaluate to a boolean"),
            "{outcome:?}"
        );
    }

    #[test]
    fn the_fuel_budget_is_a_deterministic_timeout_that_fails_closed() {
        // A comprehension over a 200-element list cannot finish inside 64 steps. No clock is read,
        // so the "timeout" is reproducible: the same bundle exhausts the same fuel, every time.
        let items: Vec<Value> = (0..200).map(|index| json!(index)).collect();
        let resource = desired(
            "v1",
            "ConfigMap",
            "big",
            json!({ "metadata": { "name": "big" }, "data": { "items": items } }),
        );
        let config =
            PolicyGateConfig::default().with_cel_budget(CelBudget::default().with_steps(64));
        let gate = PolicyGate::with_config(config);
        let rules = rule_set(vec![PolicyRule::new(
            "slow",
            PolicyEnforcement::Warn,
            "object.data.items.all(x, x >= 0)",
        )]);

        let first = evaluate(&gate, &rules, std::slice::from_ref(&resource));
        assert!(
            !first.allowed(),
            "exhausted fuel must fail closed: {first:?}"
        );
        let violation = &first.violations[0];
        assert_eq!(violation.enforcement, PolicyEnforcement::Enforce);
        assert!(
            violation.message.contains("ran out of fuel"),
            "{violation:?}"
        );

        let second = evaluate(&gate, &rules, &[resource]);
        assert_eq!(
            first.violations, second.violations,
            "fuel exhaustion must be deterministic, not timing dependent"
        );
    }

    #[test]
    fn the_total_step_budget_stops_the_pass_and_refuses_it() {
        // Even with a generous per-expression budget, the *pass* has a ceiling: the gate refuses
        // rather than evaluating only part of the bundle.
        let resources: Vec<DesiredResource> = (0..16)
            .map(|index| deployment(&format!("web-{index}"), false, "ghcr.io/example/app:1"))
            .collect();
        let gate = PolicyGate::with_config(PolicyGateConfig::default().with_total_steps(20));
        let rules = rule_set(vec![PolicyRule::new(
            "label",
            PolicyEnforcement::Warn,
            "object.metadata.labels.contains(\"cost-center\")",
        )]);
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(!outcome.allowed(), "{outcome:?}");
        assert!(
            outcome
                .violations
                .iter()
                .any(|violation| violation.rule == "<step-budget>"),
            "the pass must report the exhausted budget: {outcome:?}"
        );
    }

    #[test]
    fn secret_payloads_are_redacted_before_evaluation() {
        let gate = PolicyGate::new();
        let resources = [secret("creds", "password", "hunter2")];

        // The policy sees the *keys* and a redacted value: this expression can only be true if the
        // payload was replaced before evaluation.
        let rules = rule_set(vec![PolicyRule::new(
            "redacted-view",
            PolicyEnforcement::Enforce,
            "object.data.password == \"<redacted>\" && \
             object.stringData[\"string-token\"] == \"<redacted>\" && \
             object.data.contains(\"password\") && size(object.data) == 1",
        )]);
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(
            outcome.allowed(),
            "a Secret must reach the evaluator with redacted values: {outcome:?}"
        );

        // And the plaintext is not in the redacted document at all.
        let mut secrets = Vec::new();
        let view = policy_view(&resources[0], &mut secrets);
        let rendered = view.to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(
            !rendered.contains(&STANDARD.encode("hunter2")),
            "{rendered}"
        );
        assert!(rendered.contains(REDACTED_SECRET_VALUE), "{rendered}");
        assert!(
            secrets.iter().any(|secret| secret == "hunter2"),
            "the plaintext must still be collected for message scrubbing: {secrets:?}"
        );
    }

    #[test]
    fn a_buggy_policy_message_can_never_exfiltrate_a_secret() {
        let gate = PolicyGate::new();
        let resources = [secret("creds", "password", "hunter2")];
        let encoded = STANDARD.encode("hunter2");

        // The operator's template quotes the plaintext *and* its base64 form; the gate scrubs both
        // before the message can reach `Application.status`.
        let rules = rule_set(vec![
            PolicyRule::new("reject-secret", PolicyEnforcement::Enforce, "false")
                .with_message(format!("leaked hunter2 and {encoded} in a policy message")),
        ]);
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(!outcome.allowed());
        let message = &outcome.violations[0].message;
        assert!(!message.contains("hunter2"), "{message}");
        assert!(!message.contains(&encoded), "{message}");
        assert!(message.contains(REDACTED_SECRET_VALUE), "{message}");
    }

    #[test]
    fn an_evaluation_error_never_quotes_a_secret_value() {
        let gate = PolicyGate::new();
        let resources = [secret("creds", "password", "hunter2")];
        // A type error on a `Secret` field: the diagnostic names types, never the payload.
        let rules = rule_set(vec![PolicyRule::new(
            "type-error-on-secret",
            PolicyEnforcement::Enforce,
            "object.data.password > 3",
        )]);
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(!outcome.allowed(), "{outcome:?}");
        let message = &outcome.violations[0].message;
        assert!(!message.contains("hunter2"), "{message}");
        assert!(message.contains("cannot order"), "{message}");
    }

    #[test]
    fn match_kinds_limits_which_resources_are_evaluated() {
        let gate = PolicyGate::new();
        let rules = rule_set(vec![
            PolicyRule::new("deployments-only", PolicyEnforcement::Enforce, "false")
                .with_match_kinds(vec!["Deployment".to_owned()]),
        ]);
        let resources = [
            deployment("web", false, "ghcr.io/example/app:1"),
            desired(
                "v1",
                "ConfigMap",
                "config",
                json!({ "metadata": { "name": "config" }, "data": { "a": "b" } }),
            ),
        ];
        let outcome = evaluate(&gate, &rules, &resources);
        assert_eq!(
            outcome.evaluated, 1,
            "only the Deployment matches: {outcome:?}"
        );
        assert_eq!(outcome.violations.len(), 1);
        assert!(outcome.violations[0].resource_key.contains("Deployment"));

        // A `group/*` pattern and `*` both match everything; an empty list matches everything.
        assert!(rules[0].matches_kind("apps", "Deployment"));
        assert!(!rules[0].matches_kind("", "ConfigMap"));
        let all = PolicyRule::new("all", PolicyEnforcement::Warn, "true")
            .with_match_kinds(vec!["*".to_owned()]);
        assert!(all.matches_kind("", "Secret"));
        let group_wildcard = PolicyRule::new("apps", PolicyEnforcement::Warn, "true")
            .with_match_kinds(vec!["apps/*".to_owned()]);
        assert!(group_wildcard.matches_kind("apps", "StatefulSet"));
        assert!(!group_wildcard.matches_kind("batch", "Job"));
    }

    #[test]
    fn rule_and_resource_budgets_fail_closed_instead_of_dropping_coverage() {
        let config = PolicyGateConfig {
            max_rules: 1,
            max_resources: 1,
            ..PolicyGateConfig::default()
        };
        let gate = PolicyGate::with_config(config);
        let rules = rule_set(vec![
            PolicyRule::new("one", PolicyEnforcement::Warn, "true"),
            PolicyRule::new("two", PolicyEnforcement::Warn, "true"),
        ]);
        let resources = [
            deployment("web", false, "ghcr.io/example/app:1"),
            deployment("worker", false, "ghcr.io/example/app:1"),
        ];
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(!outcome.allowed(), "{outcome:?}");
        assert_eq!(outcome.rules, 1);
        assert!(
            outcome
                .violations
                .iter()
                .any(|violation| violation.rule == "<rule-budget>"),
            "{outcome:?}"
        );
        assert!(
            outcome
                .violations
                .iter()
                .any(|violation| violation.rule == "<resource-budget>"),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_hundred_resources_stay_inside_a_documented_deterministic_cost_budget() {
        // `T20.2` asks for "< 25 ms over 100 rendered resources". A wall-clock assertion would be
        // machine dependent and flaky, so the contract is asserted where it is decidable: the number
        // of deterministic steps the whole evaluation charges. The step budget is what bounds the
        // wall clock, and it cannot regress silently.
        //
        // The evaluator borrows each rendered document instead of cloning it per `(rule, resource)`
        // (finding M3), so this is also the regression guard for that: the cost per pair stays
        // proportional to the expression, not to the size of the resource.
        let resources: Vec<DesiredResource> = (0..100)
            .map(|index| deployment(&format!("web-{index}"), false, "ghcr.io/example/app:1"))
            .collect();
        let gate = PolicyGate::new();
        let rules = rule_set(vec![
            PolicyRule::new("no-privileged", PolicyEnforcement::Enforce, NO_PRIVILEGED)
                .with_match_kinds(vec!["Deployment".to_owned()]),
            PolicyRule::new(
                "approved-registry",
                PolicyEnforcement::Enforce,
                "object.spec.template.spec.containers.all(c, c.image.startsWith(\"ghcr.io/example/\"))",
            ),
            PolicyRule::new(
                "cost-center",
                PolicyEnforcement::Warn,
                "object.metadata.labels.contains(\"cost-center\")",
            ),
        ]);
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(outcome.allowed(), "{outcome:?}");
        assert_eq!(outcome.evaluated, 300);
        assert!(
            outcome.steps < 100_000,
            "100 resources x 3 rules must stay inside a deterministic step budget: {} steps",
            outcome.steps
        );
        assert!(
            outcome.steps < DEFAULT_TOTAL_STEPS,
            "the pass must not approach the total budget: {} steps",
            outcome.steps
        );
        // Determinism: the same bundle charges exactly the same number of steps, twice.
        let again = evaluate(&gate, &rules, &resources);
        assert_eq!(
            (outcome.steps, outcome.evaluated),
            (again.steps, again.evaluated),
            "cost is a counter, so it must not drift between identical passes"
        );
    }

    /// **`T20.2` finding C1:** a full advisory list must never be able to hide an `Enforce`
    /// violation. Before the fix the violation list was cut at [`MAX_POLICY_VIOLATIONS`] in
    /// evaluation order and `allowed()` ignored the truncation, so a `Warn` rule over many resources
    /// could push the blocking finding off the end and the controller would apply **and prune** a
    /// bundle the policy refused.
    ///
    /// This is the review's exact scenario: one `Warn` rule that rejects 40 resources, then one
    /// `Enforce` rule that rejects a single one of them.
    #[test]
    fn a_full_advisory_list_can_never_hide_a_blocking_violation() {
        let config_maps: Vec<DesiredResource> = (0..40)
            .map(|index| {
                desired(
                    "v1",
                    "ConfigMap",
                    &format!("config-{index}"),
                    json!({ "metadata": { "name": format!("config-{index}") } }),
                )
            })
            .collect();
        let gate = PolicyGate::new();
        let rules = rule_set(vec![
            PolicyRule::new(
                "prefer-owner-label",
                PolicyEnforcement::Warn,
                "has(object.metadata.labels) && object.metadata.labels.contains(\"owner\")",
            )
            .with_message("every ConfigMap should carry an owner label"),
            PolicyRule::new(
                "require-name",
                PolicyEnforcement::Enforce,
                "object.metadata.name != \"config-7\"",
            )
            .with_message("config-7 is not allowed"),
        ]);

        let outcome = evaluate(&gate, &rules, &config_maps);
        assert_eq!(
            outcome.violations.len(),
            MAX_POLICY_VIOLATIONS,
            "the list stays bounded: {outcome:?}"
        );
        assert!(
            outcome.truncated,
            "40 advisories over a 32-entry list is a truncation: {outcome:?}"
        );
        assert!(
            !outcome.allowed(),
            "the Enforce rule rejects config-7, so the bundle must be refused: {outcome:?}"
        );
        assert_eq!(
            outcome.blocking_count(),
            1,
            "the blocking finding must be retained: {outcome:?}"
        );
        assert!(
            !outcome.blocking_truncated,
            "a blocking finding was kept, so nothing blocking was dropped: {outcome:?}"
        );
        let blocking = outcome
            .blocking()
            .find(|violation| violation.rule == "require-name")
            .expect("the blocking violation must survive a full advisory list");
        assert!(
            blocking.resource_key.contains("config-7"),
            "the retained blocker must be the one that matters: {blocking:?}"
        );
        assert_eq!(
            outcome.advisories().count(),
            31,
            "an advisory was evicted to make room for the blocker: {outcome:?}"
        );
        assert!(
            outcome.summary().contains("1 blocking"),
            "{}",
            outcome.summary()
        );

        // The same bundle evaluated by a gate whose list holds everything: same verdict, and the
        // eviction is what the smaller bound cost — never coverage of a blocking rule.
        let roomy = PolicyGate::with_config(PolicyGateConfig {
            max_violations: 64,
            ..PolicyGateConfig::default()
        });
        let full = evaluate(&roomy, &rules, &config_maps);
        assert!(!full.allowed(), "{full:?}");
        assert!(!full.truncated, "{full:?}");
        assert_eq!(full.advisories().count(), 40, "{full:?}");
    }

    /// **`T20.2` finding C1, second half:** when *every* retained finding is blocking, one is
    /// dropped — and that must still refuse the bundle and say so. A synthetic finding (a compile
    /// error, the rule budget, the node budget, the step budget) goes through exactly this path, so
    /// it can never be silently lost either.
    #[test]
    fn blocking_truncation_still_refuses_the_bundle_and_says_so() {
        let config = PolicyGateConfig {
            max_violations: 2,
            ..PolicyGateConfig::default()
        };
        let gate = PolicyGate::with_config(config);
        let rules = rule_set(
            (0..3)
                .map(|index| {
                    PolicyRule::new(
                        format!("blocking-{index}"),
                        PolicyEnforcement::Enforce,
                        "false",
                    )
                })
                .collect(),
        );
        let outcome = evaluate(
            &gate,
            &rules,
            &[deployment("web", false, "ghcr.io/example/app:1")],
        );
        assert_eq!(outcome.violations.len(), 2);
        assert!(
            outcome.blocking_truncated,
            "a third blocking finding cannot fit: {outcome:?}"
        );
        assert!(
            !outcome.allowed(),
            "a dropped blocking finding still refuses the bundle: {outcome:?}"
        );
        assert_eq!(outcome.blocking_count(), 3);
        assert!(
            outcome.summary().contains("not listed"),
            "the summary must admit the dropped finding: {}",
            outcome.summary()
        );

        // A compile error is blocking too: a full advisory list may not hide it.
        let gate = PolicyGate::with_config(PolicyGateConfig {
            max_violations: 2,
            ..PolicyGateConfig::default()
        });
        let rules = rule_set(vec![
            PolicyRule::new("a", PolicyEnforcement::Warn, "false"),
            PolicyRule::new("b", PolicyEnforcement::Warn, "false"),
            PolicyRule::new(
                "broken",
                PolicyEnforcement::Warn,
                "object.spec.containers.all(c,",
            ),
        ]);
        let outcome = evaluate(
            &gate,
            &rules,
            &[deployment("web", true, "ghcr.io/example/app:1")],
        );
        assert_eq!(outcome.compile_errors.len(), 1);
        assert!(
            !outcome.allowed(),
            "a compile error must block even when the list is full of advisories: {outcome:?}"
        );
        assert!(
            outcome
                .blocking()
                .any(|violation| violation.rule == "broken"),
            "{outcome:?}"
        );

        // ... and so must the synthesized rule/resource/step budget findings.
        let gate = PolicyGate::with_config(PolicyGateConfig {
            max_violations: 2,
            max_rules: 1,
            max_resources: 1,
            ..PolicyGateConfig::default()
        });
        let rules = rule_set(vec![
            PolicyRule::new("advises", PolicyEnforcement::Warn, "false"),
            PolicyRule::new("never-runs", PolicyEnforcement::Warn, "true"),
        ]);
        let outcome = evaluate(
            &gate,
            &rules,
            &[
                deployment("web", false, "ghcr.io/example/app:1"),
                deployment("api", false, "ghcr.io/example/app:1"),
            ],
        );
        assert!(
            outcome
                .blocking()
                .any(|violation| violation.rule == "<rule-budget>"),
            "the rule-budget finding must survive a warning: {outcome:?}"
        );
        assert!(
            outcome
                .blocking()
                .any(|violation| violation.rule == "<resource-budget>"),
            "the resource-budget finding must survive a warning: {outcome:?}"
        );
        assert!(!outcome.allowed(), "{outcome:?}");
    }

    /// **`T20.2` finding M2:** the input document is checked against the JSON node budget **before**
    /// evaluation, and an over-budget resource is refused instead of skipped. Skipping it would be a
    /// policy bypass that a large (or hostile) manifest could trigger at will.
    #[test]
    fn a_resource_over_the_node_budget_fails_closed_before_evaluation() {
        let config = PolicyGateConfig {
            cel: CelBudget {
                json_nodes: 8,
                ..CelBudget::default()
            },
            ..PolicyGateConfig::default()
        };
        let gate = PolicyGate::with_config(config);
        let rules = rule_set(vec![PolicyRule::new(
            "always-true",
            PolicyEnforcement::Enforce,
            "true",
        )]);
        let big = desired(
            "v1",
            "ConfigMap",
            "big",
            json!({ "metadata": { "name": "big" }, "data": { "a": "b", "c": "d", "e": "f" } }),
        );
        let small = desired(
            "v1",
            "ConfigMap",
            "small",
            json!({ "metadata": { "name": "small" } }),
        );

        let outcome = evaluate(&gate, &rules, &[big, small]);
        assert!(
            !outcome.allowed(),
            "an over-budget document must fail closed: {outcome:?}"
        );
        let violation = outcome
            .violations
            .iter()
            .find(|violation| violation.rule == "<node-budget>")
            .expect("the refusal must be reported");
        assert!(violation.is_blocking());
        assert!(
            violation.resource_key.contains("ConfigMap") && violation.resource_key.contains("big"),
            "the refusal must name the resource: {violation:?}"
        );
        assert_eq!(
            outcome.evaluated, 1,
            "the refused document is not evaluated at all: {outcome:?}"
        );
    }

    /// **`T20.2` finding M5:** `matchKinds` written in `apiVersion` shape (`v1/Secret`,
    /// `apps/v1/Deployment`) is normalized to GroupKind. Matching nothing would be the worst
    /// outcome available: a rule that matches nothing allows everything.
    #[test]
    fn api_version_shaped_match_kinds_are_normalized_instead_of_matching_nothing() {
        let gate = PolicyGate::new();
        for (pattern, group, kind) in [
            ("v1/Secret", "", "Secret"),
            ("apps/v1/Deployment", "apps", "Deployment"),
            ("v1/ConfigMap", "", "ConfigMap"),
            ("batch/v1/Job", "batch", "Job"),
        ] {
            let rule = PolicyRule::new("rejects", PolicyEnforcement::Enforce, "false")
                .with_match_kinds(vec![pattern.to_owned()]);
            assert!(
                rule.matches_kind(group, kind),
                "{pattern} must match {group}/{kind}"
            );
            assert!(
                !rule.matches_kind(group, "Unrelated"),
                "{pattern} must not match every kind"
            );
        }
        // Normalization is not a wildcard: an unrelated apiVersion still does not match a kind.
        let rule = PolicyRule::new("rejects", PolicyEnforcement::Enforce, "false")
            .with_match_kinds(vec!["v1/Secret".to_owned()]);
        assert!(!rule.matches_kind("apps", "Deployment"));

        // The `ConfigMap` form of a rule normalizes too, so an operator writing the manifest shape
        // in `ferriscd-policies-cm` is not silently bypassed.
        let data = BTreeMap::from([(
            "no-plain-secrets".to_owned(),
            "enforcement: Enforce\nmatchKinds: [\"v1/Secret\"]\nexpression: \"false\"".to_owned(),
        )]);
        let rules = rules_from_configmap_data("ferriscd-policies-cm", &data).expect("must parse");
        assert_eq!(rules[0].match_kinds, vec!["Secret".to_owned()]);
        let resources = [
            secret("creds", "password", "hunter2"),
            deployment("web", false, "ghcr.io/example/app:1"),
        ];
        let outcome = evaluate(&gate, &rules, &resources);
        assert!(
            !outcome.allowed() && outcome.evaluated == 1,
            "the normalized rule must match the Secret and only the Secret: {outcome:?}"
        );

        // A version-looking *group* is left alone: only a real `vN[alpha|beta]N` segment is dropped.
        assert_eq!(normalize_match_kind("apps/Deployment"), "apps/Deployment");
        assert_eq!(normalize_match_kind("v1/Secret"), "Secret");
        assert_eq!(
            normalize_match_kind("apps/v1/Deployment"),
            "apps/Deployment"
        );
        assert_eq!(
            normalize_match_kind("velero.io/v1/Backup"),
            "velero.io/Backup"
        );
        assert_eq!(
            normalize_match_kind("versions.example.com/v1/Thing"),
            "versions.example.com/Thing"
        );
    }

    #[test]
    fn the_gate_is_pure_deterministic_and_reuses_compiled_programs() {
        let config = PolicyGateConfig {
            max_cached_programs: 2,
            ..PolicyGateConfig::default()
        };
        let gate = PolicyGate::with_config(config);
        let rules = rule_set(vec![
            PolicyRule::new("no-privileged", PolicyEnforcement::Enforce, NO_PRIVILEGED),
            PolicyRule::new(
                "cost-center",
                PolicyEnforcement::Warn,
                "has(object.metadata.labels)",
            ),
        ]);
        let resources = [deployment("web", true, "ghcr.io/example/app:1")];

        let first = evaluate(&gate, &rules, &resources);
        assert_eq!(gate.cached_programs(), 2);
        let second = evaluate(&gate, &rules, &resources);
        assert_eq!(
            first, second,
            "the cache must never change the verdict: the gate is a pure function of its input"
        );

        // The cache is bounded: two more distinct expressions compile but are not retained.
        let more = rule_set(vec![
            PolicyRule::new("a", PolicyEnforcement::Warn, "true"),
            PolicyRule::new("b", PolicyEnforcement::Warn, "false"),
        ]);
        let outcome = evaluate(&gate, &more, &resources);
        assert!(
            outcome.allowed(),
            "a Warn rule that rejects only advises: {outcome:?}"
        );
        assert!(
            gate.cached_programs() <= 2,
            "the program cache must stay bounded: {} entries",
            gate.cached_programs()
        );
    }

    #[test]
    fn a_rego_rule_without_an_evaluator_is_refused_instead_of_skipped() {
        // OPA/Rego is optional (`opa-policy`). Without a wired evaluator the rule is a compile
        // error and therefore blocks: a Rego policy silently ignored would be a bypass.
        let gate = PolicyGate::new();
        assert!(gate.rego.is_none());
        let rules = rule_set(vec![
            PolicyRule::new(
                "rego",
                PolicyEnforcement::Warn,
                "package ferriscd\nallow = true",
            )
            .with_engine(PolicyRuleEngine::Rego),
        ]);
        let outcome = evaluate(
            &gate,
            &rules,
            &[deployment("web", false, "ghcr.io/example/app:1")],
        );
        assert!(!outcome.allowed(), "{outcome:?}");
        assert_eq!(outcome.compile_errors.len(), 1);
        assert!(
            outcome.compile_errors[0].message.contains("not available"),
            "{outcome:?}"
        );
    }

    /// **`T20.2` finding H2:** a [`RegoPassBudget`] is owned by the pass that created it.
    ///
    /// Two budgets share no state, so charging one can never refuse (or un-refuse) the other — which
    /// is exactly what the previous process-global counter inside the evaluator did, and the reason
    /// a concurrent `begin_pass` could reset an in-flight pass.
    #[test]
    fn a_pass_budget_is_owned_by_its_pass() {
        let first = RegoPassBudget::new(Duration::from_millis(10));
        let second = RegoPassBudget::new(Duration::from_millis(10));
        assert_eq!(first.limit(), Some(Duration::from_millis(10)));
        assert_eq!(
            RegoPassBudget::unlimited().limit(),
            None,
            "an engine with its own per-evaluation bound declares no pass limit"
        );

        first.charge(Duration::from_millis(20));
        assert!(first.check().is_err(), "the first pass is exhausted");
        assert!(
            second.check().is_ok(),
            "an exhausted pass must not refuse an unrelated one"
        );
        assert_eq!(
            second.spent(),
            Duration::ZERO,
            "the second pass has spent nothing"
        );
        assert_eq!(
            second.remaining(),
            Some(Duration::from_millis(10)),
            "the second pass still has its whole allowance"
        );

        // Charging is saturating, so a huge elapsed time cannot wrap into a fresh allowance.
        second.charge(Duration::MAX);
        assert!(second.check().is_err());
        assert_eq!(second.remaining(), Some(Duration::ZERO));

        // An unlimited budget never refuses, whatever it is charged.
        let unlimited = RegoPassBudget::unlimited();
        unlimited.charge(Duration::from_secs(3600));
        assert!(unlimited.check().is_ok());
        assert_eq!(unlimited.remaining(), None);
    }

    /// The injected-evaluator seam is exercised in the feature build only: without `opa-policy` no
    /// host can wire an evaluator at all, which is the point of the gate.
    #[cfg(feature = "opa-policy")]
    #[test]
    fn a_wired_rego_evaluator_is_consulted_and_its_errors_fail_closed() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        #[derive(Debug)]
        struct Scripted {
            allow: bool,
            passes: AtomicUsize,
            calls: AtomicUsize,
        }
        impl RegoEvaluator for Scripted {
            fn evaluate(
                &self,
                _pass: &RegoPassBudget,
                _policy: &str,
                _entrypoint: &str,
                app: &Value,
                object: &Value,
            ) -> Result<bool, String> {
                assert!(
                    app.get("project").is_some(),
                    "the app facts must be injected"
                );
                assert!(object.get("kind").is_some(), "the object must be injected");
                self.calls.fetch_add(1, AtomicOrdering::Relaxed);
                Ok(self.allow)
            }

            fn begin_pass(&self) -> RegoPassBudget {
                self.passes.fetch_add(1, AtomicOrdering::Relaxed);
                RegoPassBudget::new(Duration::from_secs(1))
            }
        }

        let rules = rule_set(vec![
            PolicyRule::new(
                "rego-allow",
                PolicyEnforcement::Enforce,
                "package ferriscd\nallow",
            )
            .with_engine(PolicyRuleEngine::Rego),
        ]);
        let resource = deployment("web", false, "ghcr.io/example/app:1");

        let scripted = Arc::new(Scripted {
            allow: true,
            passes: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        });
        let allowing = PolicyGate::new().with_rego(scripted.clone());
        assert!(evaluate(&allowing, &rules, std::slice::from_ref(&resource)).allowed());
        assert_eq!(
            scripted.calls.load(AtomicOrdering::Relaxed),
            1,
            "the evaluator is consulted once per matching resource"
        );
        assert_eq!(
            scripted.passes.load(AtomicOrdering::Relaxed),
            1,
            "each pass asks for its own budget, once"
        );

        let denying = PolicyGate::new().with_rego(Arc::new(Scripted {
            allow: false,
            passes: AtomicUsize::new(0),
            calls: AtomicUsize::new(0),
        }));
        let outcome = evaluate(&denying, &rules, &[resource]);
        assert!(!outcome.allowed(), "{outcome:?}");
    }

    /// **`T20.2` finding H2 at the gate seam:** every pass gets its **own** budget object, and a
    /// second pass starting can never reset an in-flight one — the previous design reset a
    /// process-global counter inside the evaluator on every `begin_pass`, so two `Application`s
    /// reconciling at once could hand each other a fresh allowance (fail-open) or spend each
    /// other's (spurious refusals).
    #[cfg(feature = "opa-policy")]
    #[test]
    fn each_pass_owns_its_rego_budget_and_runs_are_isolated() {
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        /// Records the identity of every budget it is handed, and refuses once its own budget says
        /// so.
        #[derive(Debug)]
        struct Recording {
            budgets: Mutex<Vec<usize>>,
            passes: AtomicUsize,
            /// A pass-wide charge per evaluation, so a shared budget would be exhausted twice as
            /// fast.
            charge: Duration,
        }
        impl RegoEvaluator for Recording {
            fn evaluate(
                &self,
                pass: &RegoPassBudget,
                _policy: &str,
                _entrypoint: &str,
                _app: &Value,
                _object: &Value,
            ) -> Result<bool, String> {
                let identity = std::ptr::from_ref(pass) as usize;
                let mut budgets = self
                    .budgets
                    .lock()
                    .expect("the budget recorder is never poisoned in a test");
                if !budgets.contains(&identity) {
                    budgets.push(identity);
                }
                drop(budgets);
                pass.check()?;
                pass.charge(self.charge);
                Ok(true)
            }

            fn begin_pass(&self) -> RegoPassBudget {
                self.passes.fetch_add(1, AtomicOrdering::Relaxed);
                RegoPassBudget::new(Duration::from_secs(1))
            }
        }

        let rules = rule_set(vec![
            PolicyRule::new("rego", PolicyEnforcement::Warn, "package ferriscd\nallow")
                .with_engine(PolicyRuleEngine::Rego),
        ]);
        let resources: Vec<DesiredResource> = (0..4)
            .map(|index| deployment(&format!("web-{index}"), false, "ghcr.io/example/app:1"))
            .collect();
        let recorder = Arc::new(Recording {
            budgets: Mutex::new(Vec::new()),
            passes: AtomicUsize::new(0),
            charge: Duration::from_millis(200),
        });
        let gate = Arc::new(PolicyGate::new().with_rego(recorder.clone()));

        // Two passes at the same time, each over its own bundle.
        let first = {
            let gate = gate.clone();
            let rules = rules.clone();
            let resources = resources.clone();
            std::thread::spawn(move || evaluate(&gate, &rules, &resources))
        };
        let second = evaluate(&gate, &rules, &resources);
        let first = first.join().expect("the concurrent pass must not panic");

        assert!(first.allowed(), "{first:?}");
        assert!(second.allowed(), "{second:?}");
        assert_eq!(
            recorder.passes.load(AtomicOrdering::Relaxed),
            2,
            "one budget is created per pass"
        );
        let budgets = recorder
            .budgets
            .lock()
            .expect("the budget recorder is never poisoned in a test");
        assert_eq!(
            budgets.len(),
            2,
            "the two passes must not share a budget: {budgets:?}"
        );
        // Each pass spent only its own allowance: four evaluations of 200 ms against a 1 s budget
        // would have been refused if the two passes had shared one.
        assert_eq!(first.evaluated, 4);
        assert_eq!(second.evaluated, 4);
    }

    /// The real engine, wired exactly as the controller wires it: an `Enforce` Rego rule that
    /// rejects a privileged container blocks, and the `app`/`object` roots reach the policy.
    #[cfg(feature = "opa-policy")]
    #[test]
    fn the_embedded_regorus_engine_evaluates_a_rule_through_the_gate() {
        // The policy rule is named the Kubernetes way and the Rego rule the Rego way; the engine
        // maps one onto the other (`-` → `_`), which is what keeps rule names readable.
        let policy = "package ferriscd\n\nrego_no_privileged if {\n  input.app.project == \
                      \"payments\"\n  not input.object.spec.template.spec.containers[_]\
                      .securityContext.privileged\n}\n";
        let rules = rule_set(vec![
            PolicyRule::new("rego-no-privileged", PolicyEnforcement::Enforce, policy)
                .with_match_kinds(vec!["apps/Deployment".to_owned()])
                .with_engine(PolicyRuleEngine::Rego),
        ]);
        let gate = PolicyGate::new().with_rego(Arc::new(crate::policy::RegorusEvaluator::new()));

        let compliant = evaluate(
            &gate,
            &rules,
            &[deployment("web", false, "ghcr.io/example/app:1")],
        );
        assert!(compliant.allowed(), "{compliant:?}");
        assert!(compliant.compile_errors.is_empty(), "{compliant:?}");

        let privileged = evaluate(
            &gate,
            &rules,
            &[deployment("api", true, "ghcr.io/example/app:1")],
        );
        assert!(
            !privileged.allowed(),
            "a Rego rule must block exactly like a CEL one: {privileged:?}"
        );
        assert_eq!(privileged.violations[0].rule, "rego-no-privileged");
        assert!(privileged.violations[0].is_blocking());
    }

    #[test]
    fn configmap_rules_parse_in_key_order_and_reject_malformed_entries() {
        let data: BTreeMap<String, String> = BTreeMap::from([
            (
                "no-privileged".to_owned(),
                "enforcement: Enforce\nmatchKinds: [\"apps/Deployment\"]\nexpression: \">= 1\"\n\
                 message: no privileged containers"
                    .to_owned(),
            ),
            (
                "advisory".to_owned(),
                "enforcement: Warn\nexpression: \"true\"".to_owned(),
            ),
        ]);
        let rules = rules_from_configmap_data("ferriscd-policies-cm", &data).expect("must parse");
        assert_eq!(rules.len(), 2);
        assert_eq!(
            rules[0].name, "advisory",
            "rules follow the ConfigMap key order"
        );
        assert_eq!(rules[0].enforcement, PolicyEnforcement::Warn);
        assert_eq!(rules[1].name, "no-privileged");
        assert_eq!(rules[1].enforcement, PolicyEnforcement::Enforce);
        assert_eq!(rules[1].match_kinds, vec!["apps/Deployment".to_owned()]);
        assert_eq!(
            rules[1].message.as_deref(),
            Some("no privileged containers")
        );

        // Default enforcement is `Enforce`: an omitted field must block, never wave through.
        let defaults = BTreeMap::from([("unnamed".to_owned(), "expression: \"true\"".to_owned())]);
        let parsed = rules_from_configmap_data("cm", &defaults).expect("must parse");
        assert_eq!(parsed[0].enforcement, PolicyEnforcement::Enforce);
        assert_eq!(parsed[0].engine, PolicyRuleEngine::Cel);

        // Malformed, empty, and unknown-field entries are refused: the caller must fail closed.
        for value in [
            "expression: \"".to_owned(),
            "expression: \"\"".to_owned(),
            "expression: \"true\"\nexpresion: typo".to_owned(),
            "not: a-rule".to_owned(),
        ] {
            let data = BTreeMap::from([("broken".to_owned(), value.clone())]);
            assert!(
                rules_from_configmap_data("cm", &data).is_err(),
                "a malformed rule must be refused: {value:?}"
            );
        }
    }

    #[test]
    fn project_spec_rules_are_capped_and_the_overflow_is_reported() {
        let specs: Vec<PolicyRuleSpec> = (0..(MAX_POLICY_RULES + 3))
            .map(|index| PolicyRuleSpec {
                name: format!("rule-{index}"),
                enforcement: PolicyEnforcement::Enforce,
                engine: None,
                match_kinds: Vec::new(),
                expression: "true".to_owned(),
                message: None,
            })
            .collect();
        let (rules, overflowed) = PolicyRule::set_from_project_spec(&specs);
        assert_eq!(rules.len(), MAX_POLICY_RULES);
        assert!(overflowed, "the caller must be able to refuse the overflow");
        assert_eq!(rules[0].name, "rule-0");
    }

    /// A realistic large rendered resource: an `env`-heavy `Deployment` with `containers`
    /// containers, the shape a real bundle holds (a few hundred JSON nodes each).
    fn heavy_deployment(index: usize, containers: usize) -> DesiredResource {
        let containers: Vec<Value> = (0..containers)
            .map(|position| {
                json!({
                    "name": format!("c-{position}"),
                    "image": "ghcr.io/example/app:1.2.3",
                    "args": ["--serve", "--metrics", "--verbose"],
                    "env": (0..8)
                        .map(|var| json!({ "name": format!("VAR_{var}"), "value": "x" }))
                        .collect::<Vec<_>>(),
                    "resources": { "limits": { "cpu": "100m", "memory": "128Mi" } },
                    "securityContext": { "privileged": false },
                })
            })
            .collect();
        let name = format!("web-{index}");
        desired(
            "apps/v1",
            "Deployment",
            &name,
            json!({
                "metadata": {
                    "name": name,
                    "namespace": "payments",
                    "labels": { "cost-center": "cc-42", "app": name },
                },
                "spec": { "replicas": 2, "template": { "spec": { "containers": containers } } },
            }),
        )
    }

    /// **`T20.2` finding H1, at the pass level:** the pass budget bounds *work*, so a bundle whose
    /// documents are large costs proportionally more fuel and is refused by a budget that a small
    /// bundle fits inside.
    ///
    /// The previous counter moved once per AST node, so the same rule over a 10x larger document
    /// charged the same few steps while copying 10x more JSON — the budget bounded the policy text,
    /// not the CPU. This asserts the step-vs-size relationship the gate relies on and that the
    /// refusal happens *before* the copy, so an exhausted pass really stops working.
    #[test]
    fn the_pass_budget_bounds_work_proportional_to_the_bundle() {
        // A rule that must copy each whole document (the worst case, and the one a careless policy
        // writes): `size(object)` reads the root.
        let rules = rule_set(vec![
            PolicyRule::new(
                "whole-document",
                PolicyEnforcement::Warn,
                "size(object) > 0",
            )
            .with_match_kinds(vec!["apps/Deployment".to_owned()]),
        ]);
        let small: Vec<DesiredResource> = (0..4).map(|index| heavy_deployment(index, 2)).collect();
        let large: Vec<DesiredResource> = (0..4).map(|index| heavy_deployment(index, 20)).collect();

        let probe = evaluate(&PolicyGate::new(), &rules, &small);
        assert!(probe.allowed(), "{probe:?}");
        let small_nodes: usize = small.len() * 2 * 40; // a lower bound, for the message only
        assert!(
            probe.steps as usize >= small_nodes || probe.steps > 0,
            "{:?}",
            probe.steps
        );

        // The same four resources with 10x the containers cost markedly more fuel ...
        let big = evaluate(&PolicyGate::new(), &rules, &large);
        assert!(big.allowed(), "{big:?}");
        assert!(
            big.steps > probe.steps * 4,
            "fuel must scale with the rendered documents, not just with the rule: {} vs {}",
            probe.steps,
            big.steps
        );

        // ... so a pass budget that comfortably fits the small bundle must refuse the large one,
        // and refuse it as a blocking budget finding (never a silent partial evaluation).
        let tight =
            PolicyGate::with_config(PolicyGateConfig::default().with_total_steps(probe.steps + 8));
        let refused = evaluate(&tight, &rules, &large);
        assert!(!refused.allowed(), "{refused:?}");
        assert!(
            refused
                .blocking()
                .any(|violation| violation.rule == "<step-budget>"),
            "an exhausted pass budget must refuse the bundle: {refused:?}"
        );
        assert!(
            evaluate(&tight, &rules, &small).allowed(),
            "the same budget still fits the bundle it was sized for"
        );
    }

    /// **`T20.2` finding M7:** every message honors `PolicyGateConfig::max_message_chars`.
    ///
    /// `Application.status` is bounded (trap T9), and a host that narrows the bound must see it
    /// applied to the policy violation itself *and* to the synthesized budget findings — the
    /// previous code always used the compile-time constant.
    #[test]
    fn the_configured_message_bound_is_applied_to_every_message() {
        const LIMIT: usize = 24;
        let gate = PolicyGate::with_config(
            PolicyGateConfig::default()
                .with_max_message_chars(LIMIT)
                .with_max_rules(1),
        );
        let rules = rule_set(vec![
            PolicyRule::new("rejects", PolicyEnforcement::Enforce, "false")
                .with_message("a deliberately long operator message that cannot fit"),
            PolicyRule::new("also-rejects", PolicyEnforcement::Warn, "false"),
        ]);
        let outcome = evaluate(
            &gate,
            &rules,
            &[deployment("web", false, "ghcr.io/example/app:1")],
        );
        assert!(!outcome.allowed(), "{outcome:?}");
        for violation in &outcome.violations {
            assert!(
                violation.message.chars().count() <= LIMIT + 1,
                "{:?} is over the configured {LIMIT}-char bound: {} chars",
                violation.rule,
                violation.message.chars().count()
            );
            assert!(
                violation.message.ends_with('…'),
                "a truncated message says so: {violation:?}"
            );
        }
        assert!(
            outcome
                .violations
                .iter()
                .any(|violation| violation.rule == "<rule-budget>"),
            "the rule-budget finding is bounded too: {outcome:?}"
        );
    }

    /// **`T20.2` finding M8:** the rule and resource bounds are configurable, and the gate refuses
    /// at whichever bound it was built with.
    #[test]
    fn the_rule_and_resource_bounds_follow_the_configuration() {
        let rules = rule_set(
            (0..4)
                .map(|index| {
                    PolicyRule::new(format!("rule-{index}"), PolicyEnforcement::Warn, "true")
                })
                .collect(),
        );
        let resources = [
            deployment("web", false, "ghcr.io/example/app:1"),
            deployment("api", false, "ghcr.io/example/app:1"),
            deployment("batch", false, "ghcr.io/example/app:1"),
        ];

        // Generous bounds: everything is evaluated, nothing is refused.
        let roomy = PolicyGate::with_config(
            PolicyGateConfig::default()
                .with_max_rules(8)
                .with_max_resources(8),
        );
        let outcome = evaluate(&roomy, &rules, &resources);
        assert!(outcome.allowed(), "{outcome:?}");
        assert_eq!(outcome.rules, 4);
        assert_eq!(outcome.evaluated, 12);

        // Narrowed bounds: refused, by name, instead of narrowing silently.
        let tight = PolicyGate::with_config(
            PolicyGateConfig::default()
                .with_max_rules(2)
                .with_max_resources(2),
        );
        let outcome = evaluate(&tight, &rules, &resources);
        assert_eq!(outcome.rules, 2);
        assert_eq!(outcome.evaluated, 4);
        assert!(!outcome.allowed(), "{outcome:?}");
        assert!(
            outcome
                .violations
                .iter()
                .any(|violation| violation.rule == "<rule-budget>"),
            "{outcome:?}"
        );
        assert!(
            outcome
                .violations
                .iter()
                .any(|violation| violation.rule == "<resource-budget>"),
            "{outcome:?}"
        );
    }

    /// **NIT:** a `matchKinds` entry that names an `apiVersion` but no Kind can never match, and a
    /// rule that matches nothing allows everything. It is refused instead of silently ignored —
    /// including for a `Warn` rule, because a rule that never ran cannot be said to have advised.
    #[test]
    fn an_unmatchable_match_kinds_entry_is_refused_instead_of_matching_nothing() {
        for pattern in ["v1", "apps/v1", "v1/", "", "  "] {
            let rule = PolicyRule::new("typo", PolicyEnforcement::Warn, "true")
                .with_match_kinds(vec![pattern.to_owned()]);
            assert_eq!(
                rule.invalid_match_kind.as_deref(),
                Some(pattern),
                "{pattern:?} names no Kind and must be recorded"
            );

            let gate = PolicyGate::new();
            let outcome = evaluate(
                &gate,
                std::slice::from_ref(&rule),
                &[deployment("web", true, "docker.io/library/nginx:1")],
            );
            assert!(
                !outcome.allowed(),
                "{pattern:?} must fail closed instead of matching nothing: {outcome:?}"
            );
            assert_eq!(outcome.compile_errors.len(), 1, "{outcome:?}");
            // The exact operator-facing sentence: a copy-paste-ready message, with single spaces
            // (the source used to carry a 22-space run that reached `Application.status` verbatim).
            // Exact equality is the point: the `{pattern:?}` interpolation can itself hold spaces,
            // so only the whole sentence proves the rest of it is well formed.
            assert_eq!(
                outcome.compile_errors[0].message,
                format!(
                    "the rule's matchKinds entry {pattern:?} names an apiVersion, not a Kind, so the \
                     rule would match no resource and allow everything; write `Kind`, \
                     `group/Kind`, `group/*`, or `*`"
                ),
                "{outcome:?}"
            );
            assert_eq!(outcome.evaluated, 0, "the rule must not be evaluated");
        }

        // A valid pattern is untouched, including the manifest-shaped one that normalization keeps
        // working (`v1/Secret` -> `Secret`).
        for pattern in ["*", "Deployment", "apps/*", "apps/Deployment", "v1/Secret"] {
            let rule = PolicyRule::new("ok", PolicyEnforcement::Enforce, "true")
                .with_match_kinds(vec![pattern.to_owned()]);
            assert_eq!(
                rule.invalid_match_kind, None,
                "{pattern:?} is a usable pattern"
            );
        }

        // The `ConfigMap` parser refuses it early, so the operator sees which entry is wrong.
        let data = BTreeMap::from([(
            "no-plain-secrets".to_owned(),
            "enforcement: Enforce\nmatchKinds: [\"v1\"]\nexpression: \"false\"".to_owned(),
        )]);
        let err = rules_from_configmap_data("ferriscd-policies-cm", &data)
            .expect_err("a version-only pattern must be refused");
        let message = err.to_string();
        assert!(message.contains("unmatchable"), "{message}");
        assert!(message.contains("no-plain-secrets"), "{message}");
    }

    /// **`T20.2` findings M9 & M10:** the `PolicyAdvisory` condition lists a bounded number of
    /// advisories, reports the **total** it found (including the ones the violation budget dropped),
    /// and stays inside `Application.status`'s budget.
    #[test]
    fn the_advisory_condition_caps_and_counts_every_advisory() {
        let timestamp = Time(Timestamp::now());
        let advisory = |index: usize| PolicyViolation {
            rule: format!("advisory-{index}"),
            enforcement: PolicyEnforcement::Warn,
            resource_key: format!("apps/Deployment/payments/web-{index}"),
            message: format!(
                "advisory {index} rejected a Deployment (policy \"advisory-{index}\")"
            ),
        };

        // No advisory at all: `False`/compliant, so a stale advisory is cleared.
        let cleared = policy_advisory_condition(&[], 3, 0, Some(4), timestamp.clone());
        assert_eq!(cleared.status, ConditionStatus::False);
        assert_eq!(cleared.reason, REASON_POLICY_COMPLIANT);

        // Exactly the cap: everything is listed, with no "more" suffix.
        let listed: Vec<PolicyViolation> = (0..MAX_CONDITION_ADVISORIES).map(advisory).collect();
        let exact = policy_advisory_condition(&listed, 3, 0, Some(4), timestamp.clone());
        assert_eq!(exact.status, ConditionStatus::True);
        for index in 0..MAX_CONDITION_ADVISORIES {
            assert!(
                exact.message.contains(&format!("advisory-{index}:")),
                "{:?}",
                exact.message
            );
        }
        assert!(!exact.message.contains("more"), "{:?}", exact.message);

        // Over the cap: five are listed and the rest are counted, never silently dropped.
        let many: Vec<PolicyViolation> = (0..MAX_CONDITION_ADVISORIES + 3).map(advisory).collect();
        let capped = policy_advisory_condition(&many, 3, 0, Some(4), timestamp.clone());
        assert_eq!(capped.status, ConditionStatus::True);
        assert!(
            capped.message.contains("(+3 more)"),
            "the condition must say how many are not listed: {:?}",
            capped.message
        );
        assert!(
            !capped.message.contains("advisory-7"),
            "only the first {} are spelled out: {:?}",
            MAX_CONDITION_ADVISORIES,
            capped.message
        );
        assert!(
            capped.message.chars().count() <= MAX_POLICY_MESSAGE_CHARS,
            "{} chars",
            capped.message.chars().count()
        );

        // Advisories the **violation budget** dropped (finding M10) are counted too: the condition
        // of a refused pass must not present a truncated list as the whole story.
        let omitted = policy_advisory_condition(&listed, 3, 40, Some(4), timestamp.clone());
        assert!(
            omitted.message.contains("(+40 more)"),
            "the 40 dropped advisories must be counted: {:?}",
            omitted.message
        );
        assert!(
            !omitted.message.contains("no policy advisories"),
            "{:?}",
            omitted.message
        );

        // Every violation dropped: the message is a count, not an empty `True`.
        let all_dropped = policy_advisory_condition(&[], 3, 7, Some(4), timestamp);
        assert_eq!(all_dropped.status, ConditionStatus::True);
        assert_eq!(all_dropped.reason, REASON_POLICY_ADVISORY);
        assert!(
            all_dropped.message.contains('7'),
            "the count must survive: {:?}",
            all_dropped.message
        );
    }

    /// **`T20.2` finding M10:** an advisory evicted by a blocking finding is *counted* as omitted,
    /// so [`PolicyGateOutcome::advisory_count`] reports what the pass really found.
    #[test]
    fn a_pass_reports_how_many_advisories_it_could_not_list() {
        let config = PolicyGateConfig::default()
            .with_max_violations(3)
            .with_max_message_chars(MAX_POLICY_MESSAGE_CHARS);
        let gate = PolicyGate::with_config(config);
        let rules = rule_set(vec![
            PolicyRule::new("advises", PolicyEnforcement::Warn, "false"),
            PolicyRule::new(
                "blocks",
                PolicyEnforcement::Enforce,
                "object.metadata.name == \"never\"",
            ),
        ]);
        let resources: Vec<DesiredResource> = (0..5)
            .map(|index| deployment(&format!("web-{index}"), false, "ghcr.io/example/app:1"))
            .collect();
        let outcome = evaluate(&gate, &rules, &resources);

        assert_eq!(outcome.violations.len(), 3, "{outcome:?}");
        assert!(outcome.truncated, "{outcome:?}");
        assert!(
            outcome.advisories_omitted > 0,
            "the evicted advisories must be counted: {outcome:?}"
        );
        assert_eq!(
            outcome.advisory_count(),
            5,
            "the pass found five advisories; the count must include the ones it could not keep: \
             {outcome:?}"
        );
        assert!(
            outcome.summary().contains("5 advisory"),
            "{}",
            outcome.summary()
        );
        assert!(
            outcome.blocking_truncated && outcome.blocking_count() >= 4,
            "the blocking findings themselves overflowed a 3-entry list: {outcome:?}"
        );

        // The condition built from the pass says so instead of presenting three as the total.
        let condition = outcome.advisories_condition(None, Time(Timestamp::now()));
        assert_eq!(condition.status, ConditionStatus::True);
        assert!(
            condition.message.contains("not listed") || condition.message.contains("more"),
            "a truncated advisory list must say that it is truncated, and how many are missing: \
             {condition:?}"
        );
        assert!(
            condition.message.contains('5'),
            "the count must be the five advisories the pass found: {condition:?}"
        );
    }

    /// **`T20.2` NIT:** a payload shorter than four bytes is not collected for message scrubbing
    /// (the documented trade-off), but the *view* the evaluator sees is still redacted.
    #[test]
    fn a_short_secret_payload_is_redacted_even_though_it_is_not_scrubbed() {
        // `stringData` only: a two-character payload whose *base64* form would be long enough to
        // look like a real needle.
        let short = desired(
            "v1",
            "Secret",
            "tiny",
            json!({
                "metadata": { "name": "tiny", "namespace": "payments" },
                "type": "Opaque",
                "stringData": { "pin": "ab" },
            }),
        );
        let long = secret("creds", "password", "hunter2");

        let mut secrets = Vec::new();
        let view = policy_view(&short, &mut secrets);
        assert!(
            !view.to_string().contains("\"ab\""),
            "the evaluator must never see a short payload either: {view}"
        );
        assert!(view.to_string().contains(REDACTED_SECRET_VALUE), "{view}");
        assert!(
            secrets.is_empty(),
            "a sub-4-byte payload is not used as a scrub needle: {secrets:?}"
        );

        let mut secrets = Vec::new();
        policy_view(&long, &mut secrets);
        assert!(
            secrets.iter().any(|needle| needle == "hunter2"),
            "a 4+ byte payload is scrubbed: {secrets:?}"
        );
        assert_eq!(
            redact_secret_values("the value was hunter2", &secrets),
            format!("the value was {REDACTED_SECRET_VALUE}")
        );
    }

    /// **`T20.2` finding M5:** the gate's number comparisons are the CEL module's, so a policy
    /// guarding a large value is exact.
    #[test]
    fn large_integer_facts_are_compared_exactly() {
        let resource = desired(
            "v1",
            "ConfigMap",
            "counting",
            json!({ "metadata": { "name": "counting" }, "data": { "a": "b" } }),
        );
        let gate = PolicyGate::new();
        let rules = rule_set(vec![
            PolicyRule::new(
                "large-integers",
                PolicyEnforcement::Enforce,
                "9007199254740993 > 9007199254740992 && 9223372036854775807 > 9223372036854775806",
            )
            .with_match_kinds(vec!["ConfigMap".to_owned()]),
        ]);
        let outcome = evaluate(&gate, &rules, std::slice::from_ref(&resource));
        assert!(
            outcome.allowed(),
            "a large integer comparison must not lose precision: {outcome:?}"
        );
    }

    #[test]
    fn an_application_with_no_rules_is_a_no_op() {
        // The additive guarantee: a project (and a cluster) with no policy rules behaves exactly as
        // before `T20.2` — zero evaluations, zero violations, allowed.
        let gate = PolicyGate::new();
        let outcome = evaluate(&gate, &[], &[deployment("web", true, "anything:1")]);
        assert!(outcome.allowed());
        assert_eq!(outcome.evaluated, 0);
        assert_eq!(outcome.rules, 0);
        assert_eq!(outcome.steps, 0);
        assert!(outcome.violations.is_empty());
        assert_eq!(gate.cached_programs(), 0);
    }

    #[test]
    fn the_app_root_variable_exposes_the_application_facts() {
        let gate = PolicyGate::new();
        let rules = rule_set(vec![PolicyRule::new(
            "tenant-guard",
            PolicyEnforcement::Enforce,
            "app.project == \"payments\" && app.destination.namespace == \"payments\" && \
             app.name == \"payments-api\" && app.namespace == \"ferriscd-system\"",
        )]);
        let outcome = evaluate(
            &gate,
            &rules,
            &[deployment("web", false, "ghcr.io/example/app:1")],
        );
        assert!(outcome.allowed(), "{outcome:?}");
    }
}
