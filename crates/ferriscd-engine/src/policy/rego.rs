//! The audited, embedded **OPA/Rego** engine behind the `opa-policy` feature (`T20.2`).
//!
//! [`RegorusEvaluator`] is the [`RegoEvaluator`] implementation the controller wires when it is
//! built with `--features opa-policy`. It is a thin, defensive wrapper around
//! [`regorus`](https://github.com/microsoft/regorus) — Microsoft's pure-Rust Rego interpreter —
//! and it exists to answer one question per `(rule, resource)`: *did this policy say `true`?*
//!
//! # Why a wrapper instead of "just call the engine"
//!
//! Rego is a general-purpose policy language with a large builtin surface, and several of those
//! builtins would reopen exactly the vectors this gate exists to close: `http.send` (SSRF, and a
//! request carrying a tenant-controlled URL), `net.lookup_ip_addr` (DNS egress), `time.now_ns`
//! (non-deterministic verdicts), `opa.runtime` (environment/version disclosure). The wrapper
//! therefore enforces **four independent** defenses, in depth:
//!
//! 1. **Compile-time absence.** This crate depends on `regorus` with `default-features = false`
//!    and only `std`, so the `http`, `net`, `time`, `regex`, `glob`, `graph`, `jsonpatch`,
//!    `opa-runtime`, `uuid`, `semver`, and `urlquery` builtin modules are **not compiled in at
//!    all**. A policy that calls `http.send` cannot be evaluated even if the two checks below were
//!    removed.
//! 2. **An explicit builtin allowlist.** [`audit_policy`] rejects a policy that calls a
//!    *namespaced* builtin outside [`ALLOWED_BUILTINS`] (that is where every I/O, clock, crypto, and
//!    randomness builtin lives: `http.send`, `time.now_ns`, `rand.intn`, `crypto.*`, `io.jwt.*`,
//!    `uuid.rfc4122`, `json.patch`, …) and one that calls a denied *unqualified* builtin
//!    ([`DENIED_BUILTINS`], `trace`). Refusing unknown namespaces — rather than denying a list of
//!    known-bad ones — is what keeps a future `regorus` release from silently widening the surface.
//! 3. **Strict builtin errors.** `Engine::set_strict_builtin_errors(true)` turns any remaining
//!    unknown function into an error instead of an undefined value, so a reference we failed to
//!    classify cannot resolve to "no result" and be read as a pass.
//! 4. **Bounded work.** Policy size/line/column limits at compile time, an input-node budget, a
//!    per-evaluation wall-clock limit, and a **per-pass** wall-clock budget
//!    ([`RegoLimits::per_pass`]). Rego has no fuel counter, so those two timers *are* the step
//!    bound; when the pass budget is gone, every further evaluation in that pass fails closed
//!    instead of running.
//!
//! # The pass budget belongs to the pass
//!
//! [`RegoEvaluator::begin_pass`] *returns* a [`RegoPassBudget`] instead of resetting a counter
//! inside this evaluator. That is deliberate (`T20.2`, finding H2): a process-global counter, reset
//! by every `begin_pass`, meant two `Application`s reconciling at the same time corrupted each
//! other — one pass starting reset an in-flight pass's spent time, letting it run for another full
//! allowance (fail-open), and the same shared counter made a *concurrent* pass refuse early
//! (spurious refusals). Now `PolicyGate::evaluate` creates the budget, hands it to every evaluation
//! in the pass, and drops it, so the allowance is exactly one pass wide.
//!
//! # Policies are audited and compiled once
//!
//! `audit_policy` plus `Engine::add_policy` are the expensive half of an evaluation, and the gate
//! calls this evaluator once per `(rule, resource)` — so the same policy would otherwise be audited
//! and parsed for every resource in the bundle. One bounded cache per worker thread
//! ([`MAX_CACHED_POLICIES`] entries) keeps the audited, compiled policy and reuses it with a fresh
//! `input`. It is keyed by a hash of the policy **and verified against the policy text**, so a hash
//! collision can never evaluate the wrong policy, and it is per thread because `regorus::Engine` is
//! `Rc`-based (single-threaded by construction); nothing is shared between reconciling workers, so
//! the cache cannot become a cross-pass channel either.
//!
//! # Fail closed, exactly like CEL
//!
//! | Situation | Verdict |
//! |---|---|
//! | the policy does not parse | error → blocking violation |
//! | the entrypoint rule is not declared | error → blocking violation |
//! | the entrypoint is declared but undefined | `false` — Rego's own "deny" |
//! | the entrypoint is not a boolean | error → blocking violation |
//! | a forbidden builtin is called | error → blocking violation |
//! | the evaluation timer or the pass budget runs out | error → blocking violation |
//!
//! The third row is a deliberate reading of Rego semantics: in OPA an undefined `allow` is a
//! **deny**, so treating it as "compliant" would be the fail-open this gate forbids. A *misspelled*
//! entrypoint is not the same thing, and is reported as an error — the rule is declared nowhere, so
//! the operator has a typo to fix rather than a policy to obey.
//!
//! # Secrets never reach Rego either
//!
//! The `object` this evaluator receives is the gate's redacted view
//! ([`REDACTED_SECRET_VALUE`](super::REDACTED_SECRET_VALUE)): `Secret.data`/`stringData` values are
//! already replaced before the document is handed over, and every message the gate emits is
//! scrubbed again on the way out.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::num::NonZeroU32;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use regorus::Engine;
use regorus::utils::limits::{ExecutionTimerConfig, PolicyLengthConfig};
use serde_json::Value;

use super::gate::{RegoEvaluator, RegoPassBudget};

/// The virtual path the policy source is registered under (never a real file: this engine has no
/// filesystem access at all).
pub const POLICY_SOURCE_PATH: &str = "policy.rego";

/// Maximum length of one Rego policy, in bytes.
pub const MAX_REGO_POLICY_BYTES: usize = 8 * 1024;

/// Maximum number of lines in one Rego policy.
pub const MAX_REGO_POLICY_LINES: usize = 512;

/// Maximum column width in one Rego policy.
pub const MAX_REGO_POLICY_COLUMNS: u32 = 2_048;

/// Maximum number of JSON nodes one evaluation may receive (the redacted document plus the `app`
/// facts).
///
/// The gate already refuses a document over its own node budget; this is the evaluator's own
/// guarantee, so a host that wires it directly gets the same bound.
pub const MAX_REGO_INPUT_NODES: usize = 20_000;

/// Wall-clock limit of one `(rule, resource)` evaluation.
///
/// Rego has no fuel counter, so this is the deterministic-ish step bound for a single evaluation.
/// It matches the `T20.2` budget for a whole 100-resource pass, which leaves an evaluation that
/// genuinely needs milliseconds plenty of room and stops a pathological one immediately.
pub const DEFAULT_MAX_EVALUATION_MILLIS: u64 = 25;

/// Wall-clock budget of one **gate pass**, across every Rego rule and resource in it.
///
/// This is the ceiling the per-evaluation limit cannot provide: without it a bundle of
/// `max_rules × max_resources` evaluations could spend the per-evaluation limit 64 000 times. Once
/// the budget is gone the remaining evaluations fail closed, so the controller refuses the bundle
/// instead of grinding.
pub const DEFAULT_MAX_PASS_MILLIS: u64 = 250;

/// Namespaced Rego builtins a policy may call.
///
/// Only pure, deterministic functions. Everything else that is namespaced is refused by
/// [`audit_policy`] — including `http.send`, `net.*`, `time.*`, `crypto.*`, `io.*`, `uuid.*`,
/// `rand.*`, `opa.*`, `json.patch`, and `graph.reachable`. None of those are even compiled into
/// this build; the allowlist is the second line of defense, and it is an allowlist so that a future
/// `regorus` release adding `fs.read` fails closed by default.
pub const ALLOWED_BUILTINS: [&str; 4] = [
    "numbers.range",
    "numbers.range_step",
    "units.parse",
    "units.parse_bytes",
];

/// Unqualified Rego builtins a policy may **not** call.
///
/// Unqualified names cannot be allowlisted: a policy may legitimately call its own function or rule
/// (`my_helper(x)`), and the two are lexically indistinguishable. The interesting unqualified
/// builtins are all pure (`count`, `concat`, `startswith`, `sprintf`, …), which is why a denylist is
/// the right shape here — and why it is tiny.
pub const DENIED_BUILTINS: [&str; 1] = ["trace"];

/// Every bound [`RegorusEvaluator`] enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegoLimits {
    /// Maximum policy size in bytes.
    pub policy_bytes: usize,
    /// Maximum policy line count.
    pub policy_lines: usize,
    /// Maximum policy column width.
    pub policy_columns: u32,
    /// Maximum input nodes.
    pub input_nodes: usize,
    /// Wall-clock limit of one evaluation.
    pub evaluation: Duration,
    /// Wall-clock budget of one pass.
    pub per_pass: Duration,
}

impl Default for RegoLimits {
    fn default() -> Self {
        Self {
            policy_bytes: MAX_REGO_POLICY_BYTES,
            policy_lines: MAX_REGO_POLICY_LINES,
            policy_columns: MAX_REGO_POLICY_COLUMNS,
            input_nodes: MAX_REGO_INPUT_NODES,
            evaluation: Duration::from_millis(DEFAULT_MAX_EVALUATION_MILLIS),
            per_pass: Duration::from_millis(DEFAULT_MAX_PASS_MILLIS),
        }
    }
}

impl RegoLimits {
    /// Returns these limits with a different per-evaluation wall-clock limit.
    #[must_use]
    pub fn with_evaluation_limit(mut self, limit: Duration) -> Self {
        self.evaluation = limit;
        self
    }

    /// Returns these limits with a different per-pass budget.
    #[must_use]
    pub fn with_pass_budget(mut self, budget: Duration) -> Self {
        self.per_pass = budget;
        self
    }
}

/// How many audited-and-compiled policies one worker thread keeps.
///
/// Bounded like the CEL program cache: past the cap a policy is still audited and compiled, it is
/// just not retained, so a hostile rule set cannot grow the cache without limit.
pub const MAX_CACHED_POLICIES: usize = 64;

/// The embedded `regorus`-backed [`RegoEvaluator`].
///
/// Held across passes by the controller's [`PolicyGate`](super::PolicyGate) — which is why it holds
/// no per-pass state: the allowance lives in the [`RegoPassBudget`] its
/// [`begin_pass`](RegoEvaluator::begin_pass) returns, so concurrent passes cannot see each other's.
#[derive(Debug)]
pub struct RegorusEvaluator {
    limits: RegoLimits,
    /// How many policies this evaluator has audited and compiled (cache misses), for the test that
    /// proves repeated evaluations reuse the compiled policy.
    compilations: AtomicU64,
}

impl Default for RegorusEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl RegorusEvaluator {
    /// Builds an evaluator with the default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(RegoLimits::default())
    }

    /// Builds an evaluator with explicit bounds.
    #[must_use]
    pub fn with_limits(limits: RegoLimits) -> Self {
        Self {
            limits,
            compilations: AtomicU64::new(0),
        }
    }

    /// The bounds this evaluator enforces.
    #[must_use]
    pub fn limits(&self) -> RegoLimits {
        self.limits
    }

    /// How many times a policy was audited **and** compiled by this evaluator (i.e. missed the
    /// cache). The gate calls the evaluator once per `(rule, resource)`, so this staying at one per
    /// rule is what proves the cache works.
    #[must_use]
    pub fn compilations(&self) -> u64 {
        self.compilations.load(Ordering::Relaxed)
    }

    /// Evaluates one policy against one document, through the compile cache.
    ///
    /// The audit and the compile both happen inside the cache: a policy that was already seen is
    /// neither re-scanned nor re-parsed, and a policy that failed the audit is remembered as a
    /// failure so it keeps being refused on every evaluation (fail closed, cheaply).
    fn run(
        &self,
        policy: &str,
        entrypoint: &str,
        app: &Value,
        object: &Value,
    ) -> Result<bool, String> {
        let entrypoint = entrypoint.trim();
        if entrypoint.is_empty() {
            return Err("the Rego rule has no entrypoint name to evaluate".to_owned());
        }
        // The input is bounded and converted before the cache is locked, so no expensive work
        // happens while the thread's cache is borrowed.
        check_input_nodes(app, self.limits.input_nodes)?;
        check_input_nodes(object, self.limits.input_nodes)?;
        let input = rego_input(app, object)?;
        let limits = self.limits;
        let hash = policy_hash(policy);
        with_cache(|cache| {
            let compiled = cache.entry(hash, policy, limits, || {
                self.compilations.fetch_add(1, Ordering::Relaxed);
                audit_policy(policy, limits).and_then(|()| compile(policy, limits))
            });
            compiled?.evaluate(entrypoint, input)
        })
    }
}

impl RegoEvaluator for RegorusEvaluator {
    fn evaluate(
        &self,
        pass: &RegoPassBudget,
        policy: &str,
        entrypoint: &str,
        app: &Value,
        object: &Value,
    ) -> Result<bool, String> {
        // The pass budget is checked **before** the work, not carved up between evaluations: one
        // evaluation may overshoot by at most its own limit, so the pass stays within
        // `per_pass + per_evaluation`, and whether it is exhausted depends on the work requested
        // rather than on how it was sliced.
        pass.check()?;
        let started = Instant::now();
        let outcome = self.run(policy, entrypoint, app, object);
        // Charge the attempt, not only the successes: an always-erroring rule must not spend a
        // whole pass for free.
        pass.charge(started.elapsed());
        outcome
    }

    fn begin_pass(&self) -> RegoPassBudget {
        RegoPassBudget::new(self.limits.per_pass)
    }
}

/// One audited, compiled policy, reusable across evaluations with a fresh `input`.
#[derive(Debug)]
struct CompiledPolicy {
    /// The audit verdict: `Ok(())` when the policy was accepted, the message when it was not.
    ///
    /// Cached so a forbidden builtin is refused *every* time without re-scanning the source — and
    /// so the refusal can never be skipped by a later evaluation.
    audit: Result<(), String>,
    /// The policy's package (`data.ferriscd`) and the interpreter, when it compiled.
    program: Option<CompiledProgram>,
    /// The source the entry was built from, compared on every cache hit so a hash collision can
    /// never evaluate a different policy.
    source: String,
    /// The bounds the entry was compiled under (a mismatch rebuilds it, so an evaluator with
    /// narrower limits can never reuse a policy compiled under looser ones).
    limits: RegoLimits,
}

impl CompiledPolicy {
    fn evaluate(&mut self, entrypoint: &str, input: regorus::Value) -> Result<bool, String> {
        if let Err(refusal) = &self.audit {
            return Err(refusal.clone());
        }
        match &mut self.program {
            Some(program) => program.evaluate(entrypoint, input),
            None => Err("the Rego policy was not compiled".to_owned()),
        }
    }
}

/// The interpreter for one module, plus the package it declared.
#[derive(Debug)]
struct CompiledProgram {
    engine: Engine,
    package: String,
    /// The per-evaluation wall-clock limit the policy was compiled with.
    evaluation: Duration,
}

impl CompiledProgram {
    fn evaluate(&mut self, entrypoint: &str, input: regorus::Value) -> Result<bool, String> {
        self.engine
            .set_execution_timer_config(ExecutionTimerConfig {
                limit: self.evaluation_limit(),
                check_interval: NonZeroU32::new(1).unwrap_or(NonZeroU32::MIN),
            });
        // A typo'd entrypoint is not a deny: it is a policy that does not exist, and treating it as
        // "undefined" would hide the typo behind a permanent (safe but confusing) violation. The
        // answer is still a refusal — never a pass.
        let root = entrypoint_root(entrypoint);
        match self
            .engine
            .has_declared_rule_rooted_at(POLICY_SOURCE_PATH, &root)
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "the Rego policy declares no `{root}` rule; name the policy rule after the \
                     Rego rule (`no-privileged` is evaluated as `no_privileged`, since Rego names \
                     are identifiers)"
                ));
            }
            Err(err) => {
                return Err(format!(
                    "the Rego policy could not be inspected: {}",
                    one_line(&err)
                ));
            }
        }
        self.engine.set_input(input);
        let query = query_for(entrypoint, &self.package);
        let results = self
            .engine
            .eval_query(query, false)
            .map_err(|err| format!("the Rego policy could not be evaluated: {}", one_line(&err)))?;
        match results.result.as_slice() {
            // Rego's own semantics: an undefined rule is a deny.
            [] => Ok(false),
            [entry] => match entry.expressions.as_slice() {
                [expression] => match expression.value.as_bool() {
                    Ok(verdict) => Ok(*verdict),
                    Err(_) => Err(
                        "the Rego rule must evaluate to a boolean, or be undefined (which is a \
                         deny)"
                            .to_owned(),
                    ),
                },
                _ => Err("the Rego rule produced more than one value".to_owned()),
            },
            _ => Err("the Rego rule produced more than one value".to_owned()),
        }
    }

    /// The per-evaluation wall-clock limit.
    ///
    /// Deliberately the engine's own limit and not "whatever the pass has left": the pass budget is
    /// checked *before* each evaluation, so a single evaluation may overshoot it by at most this
    /// limit and the pass as a whole stays inside `per_pass + per_evaluation`. Narrowing it to the
    /// remainder instead would turn "the pass is nearly spent" into a per-evaluation timeout error,
    /// which reads like a policy problem rather than an exhausted allowance.
    fn evaluation_limit(&self) -> Duration {
        self.evaluation
    }
}

/// The per-worker-thread cache of audited, compiled policies.
#[derive(Default)]
struct PolicyCache {
    entries: HashMap<u64, CompiledPolicy>,
}

impl PolicyCache {
    /// Returns the entry for `policy`, building it (once) when it is absent.
    fn entry(
        &mut self,
        hash: u64,
        policy: &str,
        limits: RegoLimits,
        build: impl FnOnce() -> Result<CompiledProgram, String>,
    ) -> Result<&mut CompiledPolicy, String> {
        let reusable = self
            .entries
            .get(&hash)
            .is_some_and(|entry| entry.source == policy && entry.limits == limits);
        if !reusable {
            let (audit, program) = match build() {
                Ok(program) => (Ok(()), Some(program)),
                Err(err) => {
                    // An audit refusal is cached, a compile refusal is cached too: both have to keep
                    // refusing on every evaluation.
                    (Err(err.clone()), None)
                }
            };
            // Bounded: past the cap one arbitrary entry (a `HashMap` yields no insertion order, so
            // `keys().next()` is *some* entry — often, but not reliably, an old one) makes room, so a
            // hostile rule set cannot grow the cache without limit (nor flush it wholesale on every
            // miss).
            if self.entries.len() >= MAX_CACHED_POLICIES
                && let Some(victim) = self.entries.keys().next().copied()
            {
                self.entries.remove(&victim);
            }
            self.entries.insert(
                hash,
                CompiledPolicy {
                    audit,
                    program,
                    source: policy.to_owned(),
                    limits,
                },
            );
        }
        self.entries
            .get_mut(&hash)
            .ok_or_else(|| "the compiled policy cache lost its entry".to_owned())
    }
}

thread_local! {
    /// The compile cache of the worker thread evaluating the policy.
    ///
    /// `regorus::Engine` is `Rc`-based, so a compiled policy can only be reused from the thread that
    /// built it — which is also why nothing is shared between reconciling workers and why the cache
    /// cannot become a cross-pass channel.
    static POLICIES: RefCell<PolicyCache> = RefCell::new(PolicyCache::default());
}

/// Runs `f` against this thread's cache.
///
/// A re-entrant borrow is an error rather than a panic: `RefCell::borrow_mut` would panic here, and
/// this is runtime code reached from a reconcile worker. It cannot happen today (nothing a Rego
/// policy can call comes back into the cache), but failing closed costs one branch and removes the
/// panic path entirely.
fn with_cache<T>(f: impl FnOnce(&mut PolicyCache) -> Result<T, String>) -> Result<T, String> {
    POLICIES.with(|cache| match cache.try_borrow_mut() {
        Ok(mut cache) => f(&mut cache),
        Err(_) => Err(
            "the Rego compile cache is already borrowed, so the policy cannot be evaluated"
                .to_owned(),
        ),
    })
}

/// A stable hash of one policy source.
///
/// Only a cache key: every hit is verified against the full source, so a collision costs a rebuild
/// and never a wrong verdict.
fn policy_hash(policy: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    policy.hash(&mut hasher);
    hasher.finish()
}

/// Audits and compiles one policy into an interpreter.
///
/// `audit_policy` has already run by the time this is called (the cache does both under one entry).
fn compile(policy: &str, limits: RegoLimits) -> Result<CompiledProgram, String> {
    let mut engine = Engine::new();
    // A reference we failed to classify must be an error, never an undefined value.
    engine.set_strict_builtin_errors(true);
    engine.set_policy_length_config(PolicyLengthConfig {
        max_col: NonZeroU32::new(limits.policy_columns)
            .unwrap_or(NonZeroU32::MIN)
            .max(NonZeroU32::MIN),
        max_file_bytes: NonZeroUsize::new(limits.policy_bytes).unwrap_or(NonZeroUsize::MIN),
        max_lines: NonZeroUsize::new(limits.policy_lines).unwrap_or(NonZeroUsize::MIN),
    });
    let package = engine
        .add_policy(POLICY_SOURCE_PATH.to_owned(), policy.to_owned())
        .map_err(|err| format!("the Rego policy does not compile: {}", one_line(&err)))?;
    Ok(CompiledProgram {
        engine,
        package,
        evaluation: limits.evaluation,
    })
}

/// The rule name an entrypoint refers to inside the policy's package.
///
/// A FerrisCD policy rule is named the Kubernetes way (`no-privileged`), while a Rego rule name must
/// be an identifier. The mapping is therefore documented and mechanical: every character outside
/// `[A-Za-z0-9_]` becomes `_`, and a leading digit is prefixed with `_`. `no-privileged` is
/// evaluated as the `no_privileged` rule, and the error for a missing rule names that identifier so
/// the operator can see the mapping.
///
/// A fully qualified `data.…` entrypoint is taken verbatim, which lets a host that builds the
/// `PolicyRule` itself point at a rule anywhere in the document.
fn entrypoint_root(entrypoint: &str) -> String {
    if entrypoint.starts_with("data.") {
        let root = entrypoint.rsplit('.').next().unwrap_or(entrypoint);
        return rego_identifier(root);
    }
    rego_identifier(entrypoint)
}

/// Rewrites `name` into a valid Rego identifier (see [`entrypoint_root`]).
fn rego_identifier(name: &str) -> String {
    let mut identifier = String::with_capacity(name.len() + 1);
    for (index, character) in name.chars().enumerate() {
        let valid = character.is_ascii_alphanumeric() || character == '_';
        if !valid {
            identifier.push('_');
            continue;
        }
        if index == 0 && character.is_ascii_digit() {
            identifier.push('_');
        }
        identifier.push(character);
    }
    if identifier.is_empty() {
        return "_".to_owned();
    }
    identifier
}

/// The query that evaluates `entrypoint`: the rule name resolved inside the policy's package, or a
/// fully qualified `data.…` path used verbatim (with its root normalized like any other name).
fn query_for(entrypoint: &str, package: &str) -> String {
    if entrypoint.starts_with("data.") {
        let (prefix, root) = match entrypoint.rsplit_once('.') {
            Some((prefix, root)) => (prefix, root),
            None => (package, entrypoint),
        };
        return format!("{prefix}.{}", rego_identifier(root));
    }
    format!("{package}.{}", rego_identifier(entrypoint))
}

/// Builds the Rego input document: the `app` facts and the redacted resource, side by side.
///
/// Converted straight from the JSON tree (no serialize/parse round-trip), so the cost stays
/// proportional to the document rather than to its text.
fn rego_input(app: &Value, object: &Value) -> Result<regorus::Value, String> {
    let mut document = serde_json::Map::with_capacity(2);
    document.insert("app".to_owned(), app.clone());
    document.insert("object".to_owned(), object.clone());
    serde::Deserialize::deserialize(Value::Object(document))
        .map_err(|err| format!("the policy input could not be converted: {err}"))
}

/// Refuses an input document over the node budget (iteratively: a deep document cannot overflow
/// the stack).
fn check_input_nodes(value: &Value, limit: usize) -> Result<(), String> {
    let mut stack = vec![value];
    let mut nodes = 0_usize;
    while let Some(current) = stack.pop() {
        nodes += 1;
        if nodes > limit {
            return Err(format!(
                "the policy input is over the {limit}-node policy budget; refusing it rather than \
                 skipping it"
            ));
        }
        match current {
            Value::Array(items) => stack.extend(items.iter()),
            Value::Object(map) => stack.extend(map.values()),
            _ => {}
        }
    }
    Ok(())
}

/// Refuses a policy that is too large or calls a builtin outside the allowlist.
///
/// The scan extracts every `name(` call site and classifies it:
///
/// * a **dotted** name is a namespaced builtin (`http.send`, `numbers.range`, `json.patch`, …) —
///   a user function can never be namespaced in Rego, so every one of them must be on
///   [`ALLOWED_BUILTINS`];
/// * an **unqualified** name may be a builtin, a user function, or a rule reference, so only the
///   explicit [`DENIED_BUILTINS`] are refused.
///
/// It is a lexical check on purpose: it runs before `regorus` ever parses the policy, so a policy
/// that would reach for the network is refused with an actionable message rather than a parse
/// error, and it keeps holding if the interpreter's own feature set grows.
///
/// # Errors
///
/// A message naming the offending scope, never the policy's contents (a rule's source is
/// operator-supplied, but a diagnostic does not need to quote it).
pub fn audit_policy(policy: &str, limits: RegoLimits) -> Result<(), String> {
    if policy.len() > limits.policy_bytes {
        return Err(format!(
            "the Rego policy is {} bytes, over the {}-byte limit",
            policy.len(),
            limits.policy_bytes
        ));
    }
    if policy.lines().count() > limits.policy_lines {
        return Err(format!(
            "the Rego policy is longer than the {}-line limit",
            limits.policy_lines
        ));
    }
    for call in call_sites(policy) {
        let name = call.as_str();
        if let Some((namespace, _)) = name.split_once('.') {
            if !ALLOWED_BUILTINS.contains(&name) {
                return Err(format!(
                    "the Rego policy calls `{name}`, a builtin outside the policy allowlist \
                     (`{namespace}` is not permitted: this engine is offline and deterministic, \
                     with no network, filesystem, clock, randomness, or environment access)"
                ));
            }
            continue;
        }
        if DENIED_BUILTINS.contains(&name) {
            return Err(format!(
                "the Rego policy calls `{name}`, which this engine does not permit"
            ));
        }
    }
    Ok(())
}

/// Every `name(` call site in `policy`, as the qualified name that precedes the parenthesis.
///
/// Grouping parentheses (`(1 + 2)`) produce an empty name and are skipped; a call written across
/// lines is still found because the scan is over characters, not lines.
fn call_sites(policy: &str) -> Vec<String> {
    let bytes = policy.as_bytes();
    let mut names = Vec::new();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'(' {
            continue;
        }
        let mut start = index;
        while start > 0 {
            let previous = bytes[start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' || previous == b'.' {
                start -= 1;
            } else {
                break;
            }
        }
        if start == index {
            continue;
        }
        if let Ok(name) = std::str::from_utf8(&bytes[start..index])
            && !name.starts_with('.')
            && !name.ends_with('.')
        {
            names.push(name.to_owned());
        }
    }
    names
}

/// Renders an engine error on one line, so it survives a single-line status message.
fn one_line(err: &impl std::fmt::Display) -> String {
    err.to_string().replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// A fresh pass budget, exactly as `PolicyGate::evaluate` creates one for a pass.
    fn pass() -> RegoPassBudget {
        RegoPassBudget::new(Duration::from_secs(30))
    }

    fn object() -> Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "api", "namespace": "payments" },
            "spec": { "template": { "spec": { "containers": [{ "name": "app" }] } } }
        })
    }

    fn app() -> Value {
        json!({ "name": "payments-api", "namespace": "ferriscd-system", "project": "payments" })
    }

    const ALLOW_DEPLOYMENTS: &str = "package ferriscd\n\nallow if input.object.kind == \
                                     \"Deployment\"\n";

    #[test]
    fn a_valid_policy_allows_and_denies() {
        let evaluator = RegorusEvaluator::new();
        assert_eq!(
            evaluator.evaluate(&pass(), ALLOW_DEPLOYMENTS, "allow", &app(), &object()),
            Ok(true)
        );
        // The same policy with a rule that does not match the document: a `false` verdict, i.e. a
        // violation.
        assert_eq!(
            evaluator.evaluate(
                &pass(),
                ALLOW_DEPLOYMENTS,
                "allow",
                &app(),
                &json!({ "kind": "Secret" })
            ),
            Ok(false)
        );
        // A rule that never holds is *undefined*, which OPA treats as a deny.
        assert_eq!(
            evaluator.evaluate(
                &pass(),
                "package ferriscd\n\nallow if input.object.kind == \"Secret\"\n",
                "allow",
                &app(),
                &object()
            ),
            Ok(false)
        );
    }

    #[test]
    fn the_app_facts_are_available_to_the_policy() {
        let evaluator = RegorusEvaluator::new();
        let policy = "package ferriscd\n\nallow if {\n  input.app.project == \"payments\"\n  \
                      input.object.metadata.namespace == \"payments\"\n}\n";
        assert_eq!(
            evaluator.evaluate(&pass(), policy, "allow", &app(), &object()),
            Ok(true)
        );
    }

    #[test]
    fn a_compile_error_fails_closed() {
        let evaluator = RegorusEvaluator::new();
        let err = evaluator
            .evaluate(
                &pass(),
                "package ferriscd\n\nallow if {",
                "allow",
                &app(),
                &object(),
            )
            .expect_err("a policy that does not parse must fail closed");
        assert!(err.contains("does not compile"), "{err}");

        // A rule that is not declared is a typo, reported as such instead of silently denying.
        let err = evaluator
            .evaluate(&pass(), ALLOW_DEPLOYMENTS, "alow", &app(), &object())
            .expect_err("a missing entrypoint is an error, not a deny");
        assert!(err.contains("declares no `alow` rule"), "{err}");
    }

    #[test]
    fn a_non_boolean_result_is_refused() {
        let evaluator = RegorusEvaluator::new();
        let err = evaluator
            .evaluate(
                &pass(),
                "package ferriscd\n\nallow := 3\n",
                "allow",
                &app(),
                &object(),
            )
            .expect_err("a non-boolean result is not an invariant");
        assert!(err.contains("must evaluate to a boolean"), "{err}");
    }

    #[test]
    fn forbidden_builtins_are_refused_before_evaluation() {
        let evaluator = RegorusEvaluator::new();
        for (policy, expected) in [
            (
                "package ferriscd\n\nallow if http.send({\"method\": \"get\", \"url\": \
                 \"http://169.254.169.254\"}).status_code == 200\n",
                "http.send",
            ),
            (
                "package ferriscd\n\nallow if time.now_ns() > 0\n",
                "time.now_ns",
            ),
            (
                "package ferriscd\n\nallow if rand.intn(\"x\", 10) >= 0\n",
                "rand.intn",
            ),
            (
                "package ferriscd\n\nallow if uuid.rfc4122(\"x\") != \"\"\n",
                "uuid.rfc4122",
            ),
            (
                "package ferriscd\n\nallow if net.lookup_ip_addr(\"x\") == []\n",
                "net.lookup_ip_addr",
            ),
            (
                "package ferriscd\n\nallow if opa.runtime() != {}\n",
                "opa.runtime",
            ),
            (
                "package ferriscd\n\nallow if json.patch({}, []) == {}\n",
                "json.patch",
            ),
        ] {
            let err = evaluator
                .evaluate(&pass(), policy, "allow", &app(), &object())
                .expect_err(policy);
            assert!(
                err.contains(expected) && err.contains("allowlist"),
                "a forbidden builtin must be refused by the allowlist: {err}"
            );
        }

        // The denied unqualified builtin, and a policy that stays inside the allowlist.
        let err = evaluator
            .evaluate(
                &pass(),
                "package ferriscd\n\nallow if {\n  trace(\"hello\")\n  true\n}\n",
                "allow",
                &app(),
                &object(),
            )
            .expect_err("trace is denied");
        assert!(err.contains("trace"), "{err}");

        let allowed = "package ferriscd\n\nallow if {\n  xs := numbers.range(1, 3)\n  count(xs) \
                       == 3\n}\n";
        assert_eq!(
            evaluator.evaluate(&pass(), allowed, "allow", &app(), &object()),
            Ok(true),
            "an allowlisted builtin still works"
        );
    }

    #[test]
    fn a_policy_over_the_size_budget_is_refused() {
        let limits = RegoLimits::default();
        let oversized = format!(
            "package ferriscd\n\nallow if {{ {} }}\n",
            "true\n".repeat(MAX_REGO_POLICY_LINES + 8)
        );
        let err = audit_policy(&oversized, limits).expect_err("an oversized policy is refused");
        assert!(err.contains("line limit"), "{err}");

        let too_long = format!(
            "package ferriscd\n# {}\n",
            "x".repeat(MAX_REGO_POLICY_BYTES)
        );
        let err = audit_policy(&too_long, limits).expect_err("an oversized policy is refused");
        assert!(err.contains("byte limit"), "{err}");
    }

    #[test]
    fn the_per_evaluation_timer_is_a_timeout_that_fails_closed() {
        // Rego has no fuel counter, so the bound on one evaluation is the interpreter's own
        // execution timer. The same policy passes under the default limit and fails under a limit
        // no work can meet, which is what proves the timer is a bound on work.
        let heavy = "package ferriscd\n\nallow if {\n  xs := numbers.range(1, 20000)\n  \
                     count(xs) > 0\n}\n";
        assert_eq!(
            RegorusEvaluator::new().evaluate(&pass(), heavy, "allow", &app(), &object()),
            Ok(true),
            "the default per-evaluation limit is generous enough for real work"
        );

        let evaluator = RegorusEvaluator::with_limits(
            RegoLimits::default().with_evaluation_limit(Duration::from_nanos(1)),
        );
        let err = evaluator
            .evaluate(&pass(), heavy, "allow", &app(), &object())
            .expect_err("an evaluation over its time limit must fail closed");
        assert!(err.contains("time limit"), "{err}");
    }

    /// A policy that burns milliseconds of interpreter time, so a 1 ms pass budget is exhaustible
    /// without sleeping.
    const HEAVY: &str = "package ferriscd\n\nallow if {\n  xs := numbers.range(1, 50000)\n  \
                         count(xs) > 0\n}\n";

    #[test]
    fn the_pass_budget_stops_the_pass_and_fails_closed() {
        // The per-evaluation limit alone would let 64 000 evaluations each burn it. The pass budget
        // is the ceiling: once this pass's allowance is gone, every further evaluation in it is
        // refused.
        let evaluator = RegorusEvaluator::with_limits(
            RegoLimits::default().with_pass_budget(Duration::from_millis(1)),
        );
        let pass = evaluator.begin_pass();
        let mut refused = None;
        for _ in 0..64 {
            match evaluator.evaluate(&pass, HEAVY, "allow", &app(), &object()) {
                Ok(true) => {}
                Ok(false) => panic!("the policy must allow"),
                Err(err) => {
                    refused = Some(err);
                    break;
                }
            }
        }
        let err = refused.expect("the pass budget must be exhausted eventually");
        assert!(err.contains("budget"), "{err}");
        assert!(
            pass.spent() >= Duration::from_millis(1),
            "{}",
            pass.spent().as_micros()
        );
        assert_eq!(
            pass.remaining(),
            Some(Duration::ZERO),
            "an exhausted pass has nothing left to give"
        );

        // A **new** pass gets a fresh allowance; the exhausted one stays exhausted.
        let next = evaluator.begin_pass();
        assert_eq!(next.spent(), Duration::ZERO);
        assert_eq!(
            evaluator.evaluate(
                &next,
                "package ferriscd\n\nallow if input.object.kind == \"Deployment\"\n",
                "allow",
                &app(),
                &object()
            ),
            Ok(true)
        );
    }

    /// **`T20.2` finding H2:** the pass budget is owned by the pass, so starting a second pass
    /// cannot reset an in-flight one.
    ///
    /// The previous design kept one `AtomicU64` inside the evaluator and reset it on every
    /// `begin_pass`. Two `Application`s reconciling concurrently therefore interfered: the starting
    /// pass handed the running one a brand-new allowance (fail-open — it could spend another full
    /// budget), and the shared counter let either pass refuse the other early (spurious refusals).
    #[test]
    fn starting_a_pass_cannot_reset_an_in_flight_pass() {
        let evaluator = RegorusEvaluator::with_limits(
            RegoLimits::default().with_pass_budget(Duration::from_millis(1)),
        );

        // Pass A burns its allowance and starts being refused.
        let first = evaluator.begin_pass();
        let mut exhausted = false;
        for _ in 0..64 {
            if evaluator
                .evaluate(&first, HEAVY, "allow", &app(), &object())
                .is_err()
            {
                exhausted = true;
                break;
            }
        }
        assert!(exhausted, "pass A must run out of budget");
        let spent = first.spent();
        assert!(spent >= Duration::from_millis(1), "{}", spent.as_micros());

        // Pass B starting is exactly the event that used to reset A.
        let second = evaluator.begin_pass();
        assert_eq!(second.spent(), Duration::ZERO);
        assert_eq!(
            first.spent(),
            spent,
            "a starting pass must not reset the spent time of an in-flight one"
        );

        // ... A is still refused (no fail-open) ...
        let err = evaluator
            .evaluate(&first, HEAVY, "allow", &app(), &object())
            .expect_err("the exhausted pass must stay exhausted");
        assert!(err.contains("budget"), "{err}");

        // ... while B, which owns its own allowance, evaluates normally.
        assert_eq!(
            evaluator.evaluate(
                &second,
                "package ferriscd\n\nallow if input.object.kind == \"Deployment\"\n",
                "allow",
                &app(),
                &object()
            ),
            Ok(true),
            "an independent pass must not inherit another pass's refusal"
        );
    }

    /// **`T20.2` finding H2, concurrently:** two threads evaluating on the *same* evaluator keep
    /// separate allowances.
    #[test]
    fn concurrent_passes_keep_separate_allowances() {
        let evaluator = std::sync::Arc::new(RegorusEvaluator::with_limits(
            RegoLimits::default().with_pass_budget(Duration::from_millis(1)),
        ));

        // Thread A burns its whole pass budget and reports how much it spent.
        let burner = {
            let evaluator = evaluator.clone();
            std::thread::spawn(move || {
                let pass = evaluator.begin_pass();
                for _ in 0..64 {
                    if evaluator
                        .evaluate(&pass, HEAVY, "allow", &app(), &object())
                        .is_err()
                    {
                        break;
                    }
                }
                assert!(
                    evaluator
                        .evaluate(&pass, HEAVY, "allow", &app(), &object())
                        .is_err(),
                    "the burner's pass must end up exhausted"
                );
                pass.spent()
            })
        };

        // The main thread runs its own pass at the same time: it must never see the burner's
        // spending (no spurious refusal) and its own spending must never forgive the burner's.
        let pass = evaluator.begin_pass();
        assert_eq!(
            evaluator.evaluate(
                &pass,
                "package ferriscd\n\nallow if input.object.kind == \"Deployment\"\n",
                "allow",
                &app(),
                &object()
            ),
            Ok(true),
            "a concurrent pass must not be refused for another pass's spending"
        );
        let own = pass.spent();
        let burner_spent = burner.join().expect("the burning thread must not panic");
        assert!(burner_spent >= Duration::from_millis(1), "{burner_spent:?}");
        assert!(
            own < burner_spent,
            "each pass must account its own work: {own:?} vs {burner_spent:?}"
        );
    }

    /// **`T20.2` finding M6:** the audit and the compile happen once per policy, not once per
    /// `(rule, resource)`.
    ///
    /// The gate calls this evaluator for every resource in the bundle; re-auditing and re-parsing
    /// the same Rego source thousands of times was the dominant cost of a Rego rule set.
    #[test]
    fn a_policy_is_audited_and_compiled_once_per_rule() {
        // Unique to this test: the cache is per thread and therefore outlives a single test.
        let policy = "package ferriscd\n# compile-cache probe\n\nallow if \
                      input.object.kind == \"Deployment\"\n";
        let evaluator = RegorusEvaluator::new();
        for _ in 0..8 {
            assert_eq!(
                evaluator.evaluate(&pass(), policy, "allow", &app(), &object()),
                Ok(true)
            );
        }
        assert_eq!(
            evaluator.compilations(),
            1,
            "eight evaluations of one policy must audit and compile it once"
        );

        // A *different* policy compiles separately, and the cached one keeps working.
        assert_eq!(
            evaluator.evaluate(
                &pass(),
                "package ferriscd\n# second compile-cache probe\n\nallow if true\n",
                "allow",
                &app(),
                &object()
            ),
            Ok(true)
        );
        assert_eq!(evaluator.compilations(), 2);
        assert_eq!(
            evaluator.evaluate(&pass(), policy, "allow", &app(), &object()),
            Ok(true)
        );
        assert_eq!(
            evaluator.compilations(),
            2,
            "the first policy must not be recompiled"
        );

        // A refused policy is remembered as refused — it must keep failing closed, and it must not
        // be re-scanned on every evaluation.
        let forbidden = "package ferriscd\n# forbidden probe\n\nallow if \
                         http.send({\"method\": \"get\"}) != {}\n";
        for _ in 0..3 {
            let err = evaluator
                .evaluate(&pass(), forbidden, "allow", &app(), &object())
                .expect_err("a forbidden builtin must be refused every time");
            assert!(err.contains("http.send"), "{err}");
        }
        assert_eq!(
            evaluator.compilations(),
            3,
            "the refused policy is audited once, not once per evaluation"
        );

        // A wrong hash never evaluates the wrong policy: entries are verified against the source.
        let other = "package ferriscd\n# collision probe\n\nallow if true\n";
        assert_eq!(
            evaluator.evaluate(&pass(), other, "allow", &app(), &object()),
            Ok(true)
        );
        assert_eq!(
            evaluator.evaluate(&pass(), policy, "allow", &app(), &object()),
            Ok(true)
        );
    }

    #[test]
    fn an_over_budget_input_is_refused() {
        let limits = RegoLimits {
            input_nodes: 4,
            ..RegoLimits::default()
        };
        let evaluator = RegorusEvaluator::with_limits(limits);
        let err = evaluator
            .evaluate(&pass(), ALLOW_DEPLOYMENTS, "allow", &app(), &object())
            .expect_err("an input over the node budget must fail closed");
        assert!(err.contains("node policy budget"), "{err}");
    }

    #[test]
    fn a_policy_rule_name_maps_onto_a_rego_identifier() {
        // `AppProject.spec.policyRules[].name` is a Kubernetes-style name; a Rego rule name is an
        // identifier. The mapping is mechanical and documented, and the error for a missing rule
        // names the mapped identifier so the operator can see it.
        assert_eq!(entrypoint_root("no-privileged"), "no_privileged");
        assert_eq!(entrypoint_root("apps.no-privileged"), "apps_no_privileged");
        assert_eq!(entrypoint_root("2fast"), "_2fast");
        assert_eq!(entrypoint_root("already_ok"), "already_ok");
        assert_eq!(
            query_for("no-privileged", "data.ferriscd"),
            "data.ferriscd.no_privileged"
        );

        let evaluator = RegorusEvaluator::new();
        let object = object();
        assert_eq!(
            evaluator.evaluate(
                &pass(),
                "package ferriscd\n\nno_privileged if input.object.kind == \"Deployment\"\n",
                "no-privileged",
                &app(),
                &object
            ),
            Ok(true),
            "the dashed rule name must resolve to the Rego identifier"
        );
        let err = evaluator
            .evaluate(
                &pass(),
                "package ferriscd\n\nother if true\n",
                "no-privileged",
                &app(),
                &object,
            )
            .expect_err("a missing rule is an error");
        assert!(err.contains("no_privileged"), "{err}");

        // A caller that builds the rule itself may pass a fully qualified entrypoint.
        assert_eq!(
            evaluator.evaluate(
                &pass(),
                "package ferriscd\n\nallow if input.object.kind == \"Deployment\"\n",
                "data.ferriscd.allow",
                &app(),
                &object
            ),
            Ok(true)
        );
    }

    #[test]
    fn the_call_scanner_finds_namespaced_and_unqualified_calls() {
        let names = call_sites(
            "package ferriscd\n\nallow if {\n  http.send(x)\n  count(y) > 0\n  a := (1 + 2)\n}\n",
        );
        assert!(names.contains(&"http.send".to_owned()), "{names:?}");
        assert!(names.contains(&"count".to_owned()), "{names:?}");
        assert!(
            !names.iter().any(|name| name.is_empty()),
            "grouping parentheses are not calls: {names:?}"
        );
    }

    /// The evaluator is what the controller wires: it must be usable as the trait object the gate
    /// holds (`Arc<dyn RegoEvaluator>`), which is only true if it is `Send + Sync`.
    #[test]
    fn the_evaluator_is_object_safe_and_thread_safe() {
        fn assert_evaluator<T: RegoEvaluator + Send + Sync + 'static>(_: &T) {}
        let evaluator = RegorusEvaluator::new();
        assert_evaluator(&evaluator);
        let _as_trait: std::sync::Arc<dyn RegoEvaluator> = std::sync::Arc::new(evaluator);
    }
}
