//! Project-scoped authorization (`T14.4`).
//!
//! Authentication ([`crate::auth`]) answers *who* is calling; this module answers *what they may do*
//! and *what they may see*, from one declarative policy:
//!
//! ```yaml
//! # ConfigMap ferriscd-rbac-cm, namespace ferriscd-system, key `policy.yaml`
//! rules:
//!   - subject: { kind: group, name: platform-admins }
//!     project: "*"
//!     actions: [admin]
//!   - subject: { kind: user, name: system:serviceaccount:ferriscd-system:ci }
//!     project: payments
//!     actions: [get, diff]
//!   - subject: { kind: group, name: payments-team }
//!     project: payments
//!     actions: [get, diff, sync]
//! ```
//!
//! | Term | Meaning |
//! |---|---|
//! | `subject.kind` | `user` (matches `AuthenticatedIdentity.username`) or `group` (matches one of `groups`) |
//! | `subject.name` | exact name, or `*` for every user/group |
//! | `project` | an `AppProject` name, or `*` for every project |
//! | `action` | `get`, `diff`, `sync`, `rollback`, `admin` (`admin` implies all four) |
//!
//! # Default-deny
//!
//! There is no implicit grant. An empty policy, a rule list that matches nothing, a policy that
//! could not be parsed, and an unreadable `ConfigMap` all authorize **nothing** — a broken policy
//! makes the API read-only-in-the-worst-sense (every authenticated request is refused), never
//! open. The one exception is the anonymous identity produced by
//! [`AuthPolicy::PassThrough`](crate::AuthPolicy::PassThrough), the explicit development escape
//! hatch: it is unrestricted, because refusing it would make the documented escape useless and it
//! is already the configuration that logs a loud startup warning.
//!
//! # Never leak an application's existence
//!
//! The policy is consulted *after* the `Application` is read — the project is a field of the object,
//! so there is nothing to consult before that — and the handler then applies one rule, chosen once
//! here and tested in [`crate::api`]:
//!
//! > **`403` is only ever returned to an identity that can already see the object.** An identity
//! > with *no* grant at all on the object's project receives the same `404` a nonexistent
//! > `Application` receives (identical status and identical body), so probing names tells an
//! > unauthorized caller nothing about which ones exist. A read-only identity, which can see the
//! > object, gets an honest `403` when it tries to sync it.
//!
//! Lists (`GET /api/v1/applications`, `GET /api/v1/projects`) are filtered instead: what an identity
//! may not see is simply absent, exactly as if it did not exist.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use ferriscd_controller::RbacReloadOutcome;
use ferriscd_crd::CONTROL_PLANE_NAMESPACE;
use ferriscd_engine::manifest::{YamlGuardError, parse_document};
use serde::Deserialize;

use crate::auth::AuthenticatedIdentity;

/// The `ConfigMap` the policy is read from.
pub const RBAC_CONFIGMAP_NAME: &str = "ferriscd-rbac-cm";

/// The key inside that `ConfigMap` that holds the YAML policy document.
pub const RBAC_CONFIGMAP_KEY: &str = "policy.yaml";

/// The namespace the policy is read from unless the control plane runs elsewhere.
pub const DEFAULT_RBAC_NAMESPACE: &str = CONTROL_PLANE_NAMESPACE;

/// Wildcard entry matching every user, group, project, or (inside `actions`) every action.
pub const WILDCARD: &str = "*";

/// One capability a caller can hold on a project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Read an `Application` and its live resource graph.
    Get,
    /// Compute the live, redacted diff.
    Diff,
    /// Request a manual sync.
    Sync,
    /// Request a rollback.
    Rollback,
    /// Everything, including every future action.
    Admin,
}

impl Action {
    /// Every action, `Admin` last (`Admin` implies the rest, but is not a member of them).
    pub const ALL: [Self; 5] = [
        Self::Get,
        Self::Diff,
        Self::Sync,
        Self::Rollback,
        Self::Admin,
    ];

    /// The policy spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Diff => "diff",
            Self::Sync => "sync",
            Self::Rollback => "rollback",
            Self::Admin => "admin",
        }
    }

    /// Parses one `actions:` entry.
    ///
    /// Surrounding whitespace is trimmed; anything else is `None`, which makes the whole policy
    /// invalid (a misspelled action must not quietly grant nothing — the operator would believe the
    /// rule exists).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "get" => Some(Self::Get),
            "diff" => Some(Self::Diff),
            "sync" => Some(Self::Sync),
            "rollback" => Some(Self::Rollback),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// The actions one identity holds on one project.
///
/// A small bitset: `Grant::NONE` is the default (nothing), and `allows` folds `admin` into every
/// action so a rule cannot grant "admin except sync" by accident.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Grant(u8);

const GRANT_GET: u8 = 1 << 0;
const GRANT_DIFF: u8 = 1 << 1;
const GRANT_SYNC: u8 = 1 << 2;
const GRANT_ROLLBACK: u8 = 1 << 3;
const GRANT_ADMIN: u8 = 1 << 4;

impl Grant {
    /// No capability at all.
    pub const NONE: Self = Self(0);

    /// Adds one action.
    #[must_use]
    pub fn with(self, action: Action) -> Self {
        Self(self.0 | Self::bit(action))
    }

    /// The bit of `action`.
    const fn bit(action: Action) -> u8 {
        match action {
            Action::Get => GRANT_GET,
            Action::Diff => GRANT_DIFF,
            Action::Sync => GRANT_SYNC,
            Action::Rollback => GRANT_ROLLBACK,
            Action::Admin => GRANT_ADMIN,
        }
    }

    /// Whether this grant is "nothing at all" — the condition that must never be reported as `403`.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether `action` is allowed: its own bit, or `admin`.
    #[must_use]
    pub fn allows(self, action: Action) -> bool {
        self.0 & Self::bit(action) != 0 || self.0 & GRANT_ADMIN != 0
    }

    /// Whether any capability is held (i.e. the identity may know the object exists).
    #[must_use]
    pub fn is_visible(self) -> bool {
        !self.is_empty()
    }
}

impl fmt::Debug for Grant {
    /// Renders the actions, never the raw bits: a log line should name what was allowed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let held: Vec<&str> = Action::ALL
            .into_iter()
            .filter(|action| self.0 & Self::bit(*action) != 0)
            .map(Action::as_str)
            .collect();
        write!(f, "Grant({})", held.join(","))
    }
}

/// Whether a rule subject is a user or a Kubernetes group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    /// Matches `AuthenticatedIdentity.username`.
    User,
    /// Matches one of `AuthenticatedIdentity.groups`.
    Group,
}

impl SubjectKind {
    /// The policy spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
        }
    }

    /// Parses one `subject.kind` value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "user" => Some(Self::User),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

/// One validated policy rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Whether `name` matches a username or a group.
    pub kind: SubjectKind,
    /// Username/group name, or [`WILDCARD`].
    pub name: String,
    /// `AppProject` name, or [`WILDCARD`].
    pub project: String,
    /// The actions granted.
    pub actions: BTreeSet<Action>,
}

impl Rule {
    /// Whether this rule applies to `identity` and `project`.
    #[must_use]
    pub fn matches(&self, identity: &AuthenticatedIdentity, project: &str) -> bool {
        let subject_matches = match self.kind {
            // `*` is "any user", never "any identity": an anonymous request is not a user, and it is
            // handled by `Actor::is_unrestricted` instead.
            SubjectKind::User => {
                self.name == WILDCARD
                    || identity
                        .username
                        .as_deref()
                        .is_some_and(|username| username == self.name)
            }
            SubjectKind::Group => {
                self.name == WILDCARD
                    || identity
                        .groups
                        .iter()
                        .any(|group| group.as_str() == self.name)
            }
        };
        subject_matches && (self.project == WILDCARD || self.project == project)
    }
}

/// Why a policy document could not be used.
///
/// Secret-free by construction: the document is an authorization policy, not a credential, but a
/// parse error still never quotes the surrounding YAML (a future rule may name a private group).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RbacPolicyError {
    /// The document is not YAML in the documented shape.
    #[error("the RBAC policy is not the documented `rules:` document ({reason})")]
    Malformed {
        /// A bounded explanation from the deserializer (position, never content).
        reason: String,
    },
    /// A rule names an unknown `subject.kind`.
    #[error("rule {index}: subject.kind must be `user` or `group`")]
    UnknownSubjectKind {
        /// Zero-based index of the offending rule.
        index: usize,
    },
    /// A rule names an unknown action.
    #[error("rule {index}: `{action}` is not one of get, diff, sync, rollback, admin")]
    UnknownAction {
        /// Zero-based index of the offending rule.
        index: usize,
        /// The rejected value.
        action: String,
    },
    /// A rule has no subject name, no project, or no actions.
    #[error("rule {index}: {field} must not be empty")]
    EmptyField {
        /// Zero-based index of the offending rule.
        index: usize,
        /// The field that was empty (`subject.name`, `project`, `actions`).
        field: &'static str,
    },
}

/// The authorization policy: an ordered list of rules, deny-by-default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RbacPolicy {
    rules: Vec<Rule>,
}

/// The YAML shape (`serde` side only: never exposed).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyDocument {
    #[serde(default)]
    rules: Vec<RuleDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuleDocument {
    subject: SubjectDocument,
    project: String,
    #[serde(default)]
    actions: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SubjectDocument {
    kind: String,
    name: String,
}

impl RbacPolicy {
    /// A policy with no rules: every authenticated identity is refused (default-deny).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Parses the `policy.yaml` document of `ferriscd-rbac-cm` under FerrisCD's guarded YAML
    /// parser (`ferriscd_engine::manifest::parse_document`, `T17.1`).
    ///
    /// Rejects duplicate keys and billion-laughs alias bombs without quoting any policy content
    /// (user names, group names, or project names) in error messages.
    ///
    /// # Errors
    ///
    /// [`RbacPolicyError`] for anything that is not the documented document. A caller must treat
    /// that as "deny everything" on startup or retain the last known-good policy on live reload —
    /// an unparseable policy never degrades to a permissive one.
    pub fn parse(document: &str) -> Result<Self, RbacPolicyError> {
        let parsed: PolicyDocument = parse_document(document).map_err(|err| match err {
            YamlGuardError::Budget { limit } => RbacPolicyError::Malformed {
                reason: format!("exceeds YAML parser budget ({limit})"),
            },
            YamlGuardError::Parse => RbacPolicyError::Malformed {
                reason: "the document is not valid YAML for the RBAC policy".to_owned(),
            },
        })?;
        let mut rules = Vec::with_capacity(parsed.rules.len());
        for (index, rule) in parsed.rules.into_iter().enumerate() {
            let kind = SubjectKind::parse(&rule.subject.kind)
                .ok_or(RbacPolicyError::UnknownSubjectKind { index })?;
            if rule.subject.name.trim().is_empty() {
                return Err(RbacPolicyError::EmptyField {
                    index,
                    field: "subject.name",
                });
            }
            if rule.project.trim().is_empty() {
                return Err(RbacPolicyError::EmptyField {
                    index,
                    field: "project",
                });
            }
            if rule.actions.is_empty() {
                return Err(RbacPolicyError::EmptyField {
                    index,
                    field: "actions",
                });
            }
            let mut actions = BTreeSet::new();
            for action in rule.actions {
                let parsed =
                    Action::parse(&action).ok_or_else(|| RbacPolicyError::UnknownAction {
                        index,
                        action: action.clone(),
                    })?;
                actions.insert(parsed);
            }
            rules.push(Rule {
                kind,
                name: rule.subject.name.trim().to_owned(),
                project: rule.project.trim().to_owned(),
                actions,
            });
        }
        Ok(Self { rules })
    }

    /// How many rules the policy holds (for the startup log).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Whether the policy grants nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules, in document order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// The actions `identity` holds on `project`.
    ///
    /// Rules are unioned, so a policy can grant `get` to a whole group and `sync` to one of its
    /// members. Nothing else grants anything: an identity that matches no rule gets
    /// [`Grant::NONE`].
    #[must_use]
    pub fn grants(&self, identity: &AuthenticatedIdentity, project: &str) -> Grant {
        let mut grant = Grant::NONE;
        for rule in &self.rules {
            if rule.matches(identity, project) {
                for action in &rule.actions {
                    grant = grant.with(*action);
                }
            }
        }
        grant
    }

    /// The projects (out of `candidates`) `identity` may at least see.
    ///
    /// Used to filter `GET /api/v1/projects` and, through [`Self::grants`], the application list.
    #[must_use]
    pub fn visible_projects<'a, I>(
        &self,
        identity: &AuthenticatedIdentity,
        candidates: I,
    ) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        candidates
            .into_iter()
            .filter(|project| self.grants(identity, project).is_visible())
            .map(ToOwned::to_owned)
            .collect()
    }
}

/// One `ferriscd-rbac-cm` ConfigMap change delivered to [`RbacPolicyStore::apply_event`] (`T17.1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbacConfigMapEvent {
    /// The `ferriscd-rbac-cm` ConfigMap exists with `data["policy.yaml"]` (or `None` if the key is
    /// missing).
    Applied(Option<String>),
    /// The `ferriscd-rbac-cm` ConfigMap was deleted (or omitted from a completed watch re-list).
    Deleted,
}

/// Live-reloading, snapshot-based store for the active [`RbacPolicy`] (`T17.1`).
///
/// Reads on the HTTP request hot path take an `O(1)` cloned `Arc<RbacPolicy>` snapshot so
/// concurrent requests never contend on parsing or validation. Live updates from the namespaced
/// `ferriscd-rbac-cm` watch swap the inner `Arc` atomically:
///
/// - **Valid update:** replaces the active policy immediately (`RbacReloadOutcome::Ok`).
/// - **Malformed update / missing key:** **retains the last known-good policy** (or stays
///   deny-all if startup never succeeded) and logs a content-free warning
///   (`RbacReloadOutcome::Error`).
/// - **ConfigMap deletion:** immediately transitions to [`RbacPolicy::empty`] (default-deny,
///   `RbacReloadOutcome::Deleted`).
#[derive(Clone)]
pub struct RbacPolicyStore {
    inner: Arc<RwLock<Arc<RbacPolicy>>>,
}

impl Default for RbacPolicyStore {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for RbacPolicyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RbacPolicyStore")
            .field("rule_count", &self.rule_count())
            .finish_non_exhaustive()
    }
}

impl RbacPolicyStore {
    /// Creates a store initialized with `policy`.
    #[must_use]
    pub fn new(policy: RbacPolicy) -> Self {
        Self::from_arc(Arc::new(policy))
    }

    /// Creates a store initialized with a shared `Arc<RbacPolicy>`.
    #[must_use]
    pub fn from_arc(policy: Arc<RbacPolicy>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(policy)),
        }
    }

    /// Creates a default-deny store holding [`RbacPolicy::empty`].
    #[must_use]
    pub fn empty() -> Self {
        Self::new(RbacPolicy::empty())
    }

    /// Returns an `O(1)` atomic snapshot of the currently active [`RbacPolicy`].
    #[must_use]
    pub fn snapshot(&self) -> Arc<RbacPolicy> {
        let guard = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Atomically replaces the active [`RbacPolicy`].
    pub fn replace(&self, policy: RbacPolicy) {
        let mut guard = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        *guard = Arc::new(policy);
    }

    /// Number of rules in the currently active policy snapshot.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.snapshot().rule_count()
    }

    /// Whether the currently active policy snapshot grants nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.snapshot().is_empty()
    }

    /// Applies one `ferriscd-rbac-cm` ConfigMap event according to `T17.1` fail-safe/fail-closed
    /// rules and returns the reload outcome for Prometheus metrics.
    pub fn apply_event(&self, event: RbacConfigMapEvent) -> RbacReloadOutcome {
        match event {
            RbacConfigMapEvent::Applied(Some(document)) => match RbacPolicy::parse(&document) {
                Ok(policy) => {
                    let rules = policy.rule_count();
                    self.replace(policy);
                    tracing::info!(
                        configmap = RBAC_CONFIGMAP_NAME,
                        rules,
                        "reloaded live project-scoped RBAC policy"
                    );
                    RbacReloadOutcome::Ok
                }
                Err(error) => {
                    tracing::warn!(
                        configmap = RBAC_CONFIGMAP_NAME,
                        error = %error,
                        retained_rules = self.rule_count(),
                        "live RBAC policy update failed validation; retaining last known-good policy"
                    );
                    RbacReloadOutcome::Error
                }
            },
            RbacConfigMapEvent::Applied(None) => {
                tracing::warn!(
                    configmap = RBAC_CONFIGMAP_NAME,
                    key = RBAC_CONFIGMAP_KEY,
                    retained_rules = self.rule_count(),
                    "live RBAC ConfigMap is missing key `{RBAC_CONFIGMAP_KEY}`; retaining last \
                     known-good policy"
                );
                RbacReloadOutcome::Error
            }
            RbacConfigMapEvent::Deleted => {
                self.replace(RbacPolicy::empty());
                tracing::warn!(
                    configmap = RBAC_CONFIGMAP_NAME,
                    "RBAC ConfigMap was deleted; transitioned immediately to default-deny"
                );
                RbacReloadOutcome::Deleted
            }
        }
    }
}

/// One request's authorization decisions.
///
/// Built per request from the policy and the identity the [`crate::auth`] middleware resolved; the
/// handlers ask it questions, so there is exactly one place where "no grant" and "grant without that
/// action" are distinguished.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    policy: &'a RbacPolicy,
    identity: &'a AuthenticatedIdentity,
}

impl<'a> Actor<'a> {
    /// Builds the actor for one request.
    #[must_use]
    pub fn new(policy: &'a RbacPolicy, identity: &'a AuthenticatedIdentity) -> Self {
        Self { policy, identity }
    }

    /// Whether authorization is bypassed for this request.
    ///
    /// Only the anonymous identity (the `pass-through` development escape) is unrestricted; an
    /// authenticated identity is always subject to the policy.
    #[must_use]
    pub fn is_unrestricted(self) -> bool {
        !self.identity.is_authenticated()
    }

    /// The grant on `project`.
    #[must_use]
    pub fn grant(self, project: &str) -> Grant {
        if self.is_unrestricted() {
            return Action::ALL.into_iter().fold(Grant::NONE, Grant::with);
        }
        self.policy.grants(self.identity, project)
    }

    /// Whether the caller may act on `project` at all (i.e. may learn that it exists).
    #[must_use]
    pub fn can_see(self, project: &str) -> bool {
        self.grant(project).is_visible()
    }

    /// Whether the caller may perform `action` on `project`.
    #[must_use]
    pub fn allows(self, project: &str, action: Action) -> bool {
        self.grant(project).allows(action)
    }

    /// The identity this actor was built for.
    #[must_use]
    pub fn identity(self) -> &'a AuthenticatedIdentity {
        self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(username: &str, groups: &[&str]) -> AuthenticatedIdentity {
        AuthenticatedIdentity::new(
            username,
            groups.iter().map(|group| (*group).to_owned()).collect(),
        )
    }

    const POLICY: &str = r#"
# Project-scoped RBAC for the FerrisCD API.
rules:
  - subject:
      kind: group
      name: platform-admins
    project: "*"
    actions: [admin]
  - subject:
      kind: group
      name: payments-team
    project: payments
    actions: [get, diff]
  - subject:
      kind: group
      name: payments-cd
    project: payments
    actions: [sync, rollback]
  - subject:
      kind: user
      name: system:serviceaccount:ferriscd-system:ci
    project: tenants-a
    actions: [get, diff, sync]
"#;

    #[test]
    fn the_documented_policy_parses() {
        let policy = RbacPolicy::parse(POLICY).expect("the documented policy parses");
        assert_eq!(policy.rule_count(), 4);
        assert!(!policy.is_empty());
        assert_eq!(policy.rules()[0].actions.len(), 1);
        assert_eq!(policy.rules()[1].kind, SubjectKind::Group);
        assert_eq!(policy.rules()[3].kind, SubjectKind::User);
    }

    #[test]
    fn an_empty_document_is_a_valid_deny_all_policy() {
        for document in ["", "rules: []", "# nothing at all"] {
            let policy = RbacPolicy::parse(document).expect("an empty policy is valid");
            assert!(policy.is_empty(), "{document:?}");
            assert_eq!(
                policy.grants(&identity("alice", &["platform-admins"]), "payments"),
                Grant::NONE
            );
        }
    }

    /// A policy document that is not understood must be *refused*, never partially applied: a
    /// half-read policy is a policy nobody can reason about.
    /// A predicate over the parse error, so one table can cover every rejection reason.
    type Expect = fn(&RbacPolicyError) -> bool;

    #[test]
    fn a_malformed_policy_is_refused() {
        let cases: &[(&str, Expect)] = &[
            ("rules: [", |_| true),
            (
                "rules:\n  - subject: {kind: robot, name: x}\n    project: p\n    actions: [get]\n",
                |err| matches!(err, RbacPolicyError::UnknownSubjectKind { index: 0 }),
            ),
            (
                "rules:\n  - subject: {kind: group, name: x}\n    project: p\n    actions: [read-everything]\n",
                |err| matches!(err, RbacPolicyError::UnknownAction { index: 0, .. }),
            ),
            (
                "rules:\n  - subject: {kind: group, name: x}\n    project: p\n    actions: []\n",
                |err| {
                    matches!(
                        err,
                        RbacPolicyError::EmptyField {
                            field: "actions",
                            ..
                        }
                    )
                },
            ),
            (
                "rules:\n  - subject: {kind: group, name: \"\"}\n    project: p\n    actions: [get]\n",
                |err| {
                    matches!(
                        err,
                        RbacPolicyError::EmptyField {
                            field: "subject.name",
                            ..
                        }
                    )
                },
            ),
            (
                "rules:\n  - subject: {kind: group, name: x}\n    project: \"\"\n    actions: [get]\n",
                |err| {
                    matches!(
                        err,
                        RbacPolicyError::EmptyField {
                            field: "project",
                            ..
                        }
                    )
                },
            ),
            // A typo in a *field name* is refused too (`deny_unknown_fields`): silently ignoring
            // `action:` (singular) would create a rule that grants nothing while looking correct.
            (
                "rules:\n  - subject: {kind: group, name: x}\n    project: p\n    action: [get]\n",
                |_| true,
            ),
            ("permissions: []\n", |_| true),
        ];
        for (document, predicate) in cases {
            let error =
                RbacPolicy::parse(document).expect_err(&format!("{document:?} must be refused"));
            assert!(predicate(&error), "{document:?} produced {error:?}");
        }
    }

    /// The parse error must remain strictly content-free: the document is full of group and user
    /// names, and an error (or the log line that quotes it) must not publish them.
    #[test]
    fn a_malformed_policy_error_never_quotes_the_document() {
        let document =
            "rules:\n  - subject: {kind: group, name: secret-group-name}\n    actionz: [get]\n";
        let error = RbacPolicy::parse(document).expect_err("the field name is unknown");
        let rendered = error.to_string();
        assert!(
            matches!(error, RbacPolicyError::Malformed { .. }),
            "expected Malformed, got {error:?}"
        );
        assert!(
            !rendered.contains("secret-group-name"),
            "the error must not quote the policy: {rendered}"
        );
        assert!(!rendered.contains("actionz"), "{rendered}");
    }

    #[test]
    fn a_user_rule_matches_its_username_only() {
        let policy = RbacPolicy::parse(
            r#"
rules:
  - subject: {kind: user, name: alice}
    project: payments
    actions: [get]
"#,
        )
        .expect("a policy");
        let alice = identity("alice", &[]);
        assert_eq!(
            policy.grants(&alice, "payments"),
            Grant::NONE.with(Action::Get)
        );
        assert!(policy.grants(&alice, "billing").is_empty());
        assert!(
            policy.grants(&identity("bob", &[]), "payments").is_empty(),
            "a user rule is not a group rule"
        );
        // The anonymous identity matches no `user` rule, not even a `*` one: it is not a user.
        assert!(
            policy
                .grants(&AuthenticatedIdentity::anonymous(), "payments")
                .is_empty()
        );
    }

    #[test]
    fn a_group_rule_matches_any_member_and_the_wildcard_matches_everyone() {
        let policy = RbacPolicy::parse(POLICY).expect("the documented policy parses");
        let team = identity(
            "system:serviceaccount:ferriscd-system:deployer",
            &["payments-team"],
        );
        assert_eq!(
            policy.grants(&team, "payments"),
            Grant::NONE.with(Action::Get).with(Action::Diff)
        );
        // A second rule on the same project is unioned, not overridden.
        let both = identity(
            "system:serviceaccount:ferriscd-system:deployer",
            &["payments-team", "payments-cd"],
        );
        let grant = policy.grants(&both, "payments");
        for action in [Action::Get, Action::Diff, Action::Sync, Action::Rollback] {
            assert!(
                grant.allows(action),
                "{action:?} must be granted: {grant:?}"
            );
        }
        assert!(
            !grant.allows(Action::Admin),
            "admin is never implied backwards"
        );

        let admin = identity("weird-name", &["platform-admins"]);
        for action in Action::ALL {
            assert!(
                policy.grants(&admin, "anything-at-all").allows(action),
                "the wildcard admin rule covers {action:?}"
            );
        }
        // A group rule says nothing about an identity in another group.
        assert!(
            policy
                .grants(&identity("carol", &["billing"]), "payments")
                .is_empty()
        );
    }

    #[test]
    fn a_wildcard_subject_matches_every_user() {
        let policy = RbacPolicy::parse(
            r#"
rules:
  - subject: {kind: user, name: "*"}
    project: shared
    actions: [get]
"#,
        )
        .expect("a policy");
        assert!(
            policy
                .grants(&identity("anyone", &[]), "shared")
                .allows(Action::Get)
        );
        assert!(
            policy
                .grants(&identity("someone-else", &[]), "shared")
                .allows(Action::Get)
        );
        assert!(
            !policy
                .grants(&identity("anyone", &[]), "private")
                .allows(Action::Get)
        );
    }

    /// `admin` implies every action, and `Grant` still reports what was literally granted.
    #[test]
    fn admin_implies_every_action() {
        let grant = Grant::NONE.with(Action::Admin);
        assert!(grant.is_visible());
        for action in [
            Action::Get,
            Action::Diff,
            Action::Sync,
            Action::Rollback,
            Action::Admin,
        ] {
            assert!(grant.allows(action), "{action:?}");
        }
        assert!(!Grant::NONE.allows(Action::Get));
        assert!(!Grant::NONE.is_visible());
        assert_eq!(format!("{grant:?}"), "Grant(admin)");
        assert_eq!(
            format!("{:?}", Grant::NONE.with(Action::Get).with(Action::Sync)),
            "Grant(get,sync)"
        );
    }

    #[test]
    fn every_action_round_trips_through_its_spelling() {
        for action in Action::ALL {
            assert_eq!(Action::parse(action.as_str()), Some(action));
        }
        assert_eq!(Action::parse(" get "), Some(Action::Get));
        for rejected in ["", "Admin", "GET", "write", "*"] {
            assert_eq!(Action::parse(rejected), None, "{rejected:?}");
        }
        assert_eq!(SubjectKind::parse("user"), Some(SubjectKind::User));
        assert_eq!(SubjectKind::parse(" group "), Some(SubjectKind::Group));
        assert_eq!(SubjectKind::parse("robot"), None);
        assert_eq!(SubjectKind::User.as_str(), "user");
        assert_eq!(SubjectKind::Group.as_str(), "group");
    }

    #[test]
    fn the_anonymous_identity_is_unrestricted_only_when_it_is_anonymous() {
        let policy = RbacPolicy::empty();
        let anonymous = AuthenticatedIdentity::anonymous();
        let actor = Actor::new(&policy, &anonymous);
        assert!(actor.is_unrestricted());
        assert!(actor.can_see("anything"));
        for action in Action::ALL {
            assert!(actor.allows("anything", action));
        }

        let authenticated = identity("alice", &[]);
        let actor = Actor::new(&policy, &authenticated);
        assert!(!actor.is_unrestricted());
        assert!(!actor.can_see("anything"));
        assert!(!actor.allows("anything", Action::Get));
        assert_eq!(actor.identity().username.as_deref(), Some("alice"));
    }

    #[test]
    fn the_visible_project_filter_keeps_only_permitted_projects() {
        let policy = RbacPolicy::parse(POLICY).expect("the documented policy parses");
        let team = identity("deployer", &["payments-team"]);
        assert_eq!(
            policy.visible_projects(&team, ["payments", "billing", "tenants-a"]),
            vec!["payments".to_owned()]
        );
        let admin = identity("root", &["platform-admins"]);
        assert_eq!(
            policy.visible_projects(&admin, ["payments", "billing"]),
            vec!["payments".to_owned(), "billing".to_owned()]
        );
        assert!(
            policy
                .visible_projects(&identity("nobody", &[]), ["payments"])
                .is_empty()
        );
    }

    /// `T17.1`: `RbacPolicy::parse` runs through `ferriscd_engine::manifest::parse_document`,
    /// rejecting duplicate keys and billion-laughs alias bombs without echoing user or group names.
    #[test]
    fn guarded_parser_rejects_duplicate_keys_and_alias_bombs_without_leaking_names() {
        let duplicate_keys = r#"
rules:
  - subject:
      kind: group
      name: secret-payroll-admins
    project: payments
    actions: [get]
    actions: [admin]
"#;
        let err = RbacPolicy::parse(duplicate_keys).expect_err("duplicate keys must be rejected");
        let rendered = err.to_string();
        assert!(
            matches!(err, RbacPolicyError::Malformed { .. }),
            "expected Malformed, got {err:?}"
        );
        assert!(
            !rendered.contains("secret-payroll-admins"),
            "error must never echo group/user names: {rendered}"
        );

        let alias_bomb = r#"
a: &a ["secret-group-alpha", "secret-group-alpha", "secret-group-alpha", "secret-group-alpha", "secret-group-alpha", "secret-group-alpha", "secret-group-alpha", "secret-group-alpha", "secret-group-alpha", "secret-group-alpha"]
b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]
c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]
d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]
e: &e [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]
rules: *e
"#;
        let err = RbacPolicy::parse(alias_bomb).expect_err("alias bomb must be rejected");
        let rendered = err.to_string();
        assert!(
            matches!(err, RbacPolicyError::Malformed { .. }),
            "expected Malformed, got {err:?}"
        );
        assert!(
            !rendered.contains("secret-group-alpha"),
            "error must never echo alias contents: {rendered}"
        );
    }

    /// `T17.1`: `RbacPolicyStore::apply_event` swaps valid updates atomically, retains the last
    /// known-good policy on malformed updates or missing keys, and transitions immediately to
    /// default-deny when `ferriscd-rbac-cm` is deleted.
    #[test]
    fn policy_store_hot_reloads_retains_last_good_on_error_and_fails_closed_on_delete() {
        let store = RbacPolicyStore::empty();
        assert!(store.is_empty());

        // Malformed startup update keeps empty (deny-all) policy.
        assert_eq!(
            store.apply_event(RbacConfigMapEvent::Applied(Some("rules: [".to_owned()))),
            RbacReloadOutcome::Error
        );
        assert!(store.is_empty());

        // Valid live update activates immediately.
        assert_eq!(
            store.apply_event(RbacConfigMapEvent::Applied(Some(POLICY.to_owned()))),
            RbacReloadOutcome::Ok
        );
        let payments_team = identity("alice", &["payments-team"]);
        assert!(
            store
                .snapshot()
                .grants(&payments_team, "payments")
                .allows(Action::Get)
        );
        assert_eq!(store.rule_count(), 4);

        // Malformed live update retains the last known-good policy (never wipes or widens).
        assert_eq!(
            store.apply_event(RbacConfigMapEvent::Applied(Some(
                "rules:\n  - subject: {kind: group, name: x}\n    project: '*'\n    actions: [bogus]\n"
                    .to_owned()
            ))),
            RbacReloadOutcome::Error
        );
        assert_eq!(store.rule_count(), 4);
        assert!(
            store
                .snapshot()
                .grants(&payments_team, "payments")
                .allows(Action::Get)
        );

        // Missing `policy.yaml` key also retains the last known-good policy.
        assert_eq!(
            store.apply_event(RbacConfigMapEvent::Applied(None)),
            RbacReloadOutcome::Error
        );
        assert_eq!(store.rule_count(), 4);

        // Deleting the ConfigMap transitions immediately to default-deny.
        assert_eq!(
            store.apply_event(RbacConfigMapEvent::Deleted),
            RbacReloadOutcome::Deleted
        );
        assert!(store.is_empty());
        assert!(
            !store
                .snapshot()
                .grants(&payments_team, "payments")
                .is_visible()
        );
    }
}
