//! The pure sync decision gate: should this reconcile apply anything at all?
//!
//! `v0.2` applied the whole desired set on every pass, which is neither idempotent nor cheap.
//! The gate distinguishes the four policies an `Application` can express:
//!
//! | `syncPolicy.automated` | `selfHeal` | Applies when |
//! |---|---|---|
//! | absent | — | never automatically (drift is still reported) |
//! | present | `false` | `(commit_sha, source_spec_hash)` changed since the last successful sync |
//! | present | `true` | the source changed **or** any `OutOfSync`/`Missing` resource exists, **or** (`prune` and any `Orphaned` resource) |
//! | any | any | a manual operation is requested |
//!
//! `OwnershipConflict` resources are *reported* but never act as a trigger: the object belongs to
//! another `Application`, so the apply this gate would authorize cannot succeed. Treating it as
//! drift made `selfHeal: true` execute on every reconcile forever; it is now terminal (see
//! [`DiffSummary::has_ownership_conflicts`]) and keeps `status.sync.status` at `OutOfSync`.
//!
//! # Finding H7: `spec` edits that produce no commit
//!
//! `selfHeal: false` historically compared only `commit_sha`, so editing
//! `spec.source.git.path` (a different directory in the *same* commit) never triggered a sync
//! until somebody pushed. [`source_spec_hash`] closes that hole: it hashes the canonical JSON of
//! `spec.source` + `spec.destination`, is persisted as `status.sync.lastSyncedSpecHash`, and is
//! compared alongside the revision.
//!
//! Everything here is pure (no client, no clock, no I/O), so the full truth table is testable
//! without a cluster.

use std::collections::BTreeMap;
use std::fmt;

use ferriscd_crd::{Application, ApplicationSpec};
use serde_json::{Map, Value};

use crate::diff::sha256;
use crate::diff::types::DiffSummary;

/// Why a sync was skipped.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum SkipReason {
    /// `spec.syncPolicy.automated` is absent: manual-only sync (drift is still reported).
    AutomatedDisabled,
    /// `automated.selfHeal` is `false` and the source has not changed since the last sync.
    SelfHealDisabled,
    /// Self-healing is enabled and nothing drifted: live state already matches Git.
    AlreadySynced,
    /// The `AppProject`'s deployment-governance window blocks this sync right now (`T17.4`).
    ///
    /// A window is a *governance* refusal, not a policy violation: drift is still computed and
    /// reported (`OutOfSync`), the controller still keeps `Ready=True` (`reason=SyncWindowActive`),
    /// and it requeues for the window boundary instead of waiting for an operator.
    SyncWindowDenied,
}

impl SkipReason {
    /// The wire form of this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutomatedDisabled => "automatedDisabled",
            Self::SelfHealDisabled => "selfHealDisabled",
            Self::AlreadySynced => "alreadySynced",
            Self::SyncWindowDenied => "syncWindowDenied",
        }
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AutomatedDisabled => f.write_str("automated sync is disabled"),
            Self::SelfHealDisabled => {
                f.write_str("self-heal is disabled and the source is unchanged")
            }
            Self::AlreadySynced => f.write_str("live state already matches Git"),
            Self::SyncWindowDenied => {
                f.write_str("a sync window of the AppProject blocks this sync right now")
            }
        }
    }
}

/// Why a sync was executed.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum SyncTrigger {
    /// A manual operation was requested (`ferriscd.io/operation`, CLI, API).
    Manual,
    /// The resolved commit SHA or the `spec.source`/`spec.destination` hash changed (finding H7).
    SourceChanged,
    /// The source is unchanged but live state drifted (`OutOfSync`/`Missing`).
    ///
    /// Deliberately not `OwnershipConflict`: that is terminal (never self-healed), see
    /// [`DiffSummary::has_ownership_conflicts`].
    DriftDetected,
    /// The source is unchanged and nothing drifted, but pruning is enabled and an orphan exists.
    PruneRequired,
}

impl SyncTrigger {
    /// The wire form of this trigger.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::SourceChanged => "sourceChanged",
            Self::DriftDetected => "driftDetected",
            Self::PruneRequired => "pruneRequired",
        }
    }
}

impl fmt::Display for SyncTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of the sync decision gate.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum SyncDecision {
    /// Do not apply anything; the reason is reported in `Application.status`.
    Skip(SkipReason),
    /// Apply the desired set; the trigger explains why.
    Execute(SyncTrigger),
}

impl SyncDecision {
    /// Returns whether the gate decided to apply.
    #[must_use]
    pub fn is_execute(&self) -> bool {
        matches!(self, Self::Execute(_))
    }

    /// Returns whether the gate decided to skip.
    #[must_use]
    pub fn is_skip(&self) -> bool {
        matches!(self, Self::Skip(_))
    }

    /// Returns the trigger of an [`SyncDecision::Execute`].
    #[must_use]
    pub fn trigger(&self) -> Option<SyncTrigger> {
        match self {
            Self::Execute(trigger) => Some(*trigger),
            Self::Skip(_) => None,
        }
    }

    /// Returns the reason of a [`SyncDecision::Skip`].
    #[must_use]
    pub fn skip_reason(&self) -> Option<SkipReason> {
        match self {
            Self::Skip(reason) => Some(*reason),
            Self::Execute(_) => None,
        }
    }
}

impl fmt::Display for SyncDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Skip(reason) => write!(f, "skip: {reason}"),
            Self::Execute(trigger) => write!(f, "execute: {trigger}"),
        }
    }
}

/// A `spec.source`/`spec.destination` pair that cannot be serialized to JSON.
///
/// Both types are plain strings/enums, so this is unreachable in practice — but hashing a
/// silently-empty document would make every `spec` edit invisible (the very bug the hash
/// exists to prevent), so the failure is surfaced instead of swallowed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cannot hash spec.source/spec.destination: {message}")]
pub struct SourceSpecHashError {
    /// The underlying serialization failure.
    pub message: String,
}

impl SourceSpecHashError {
    /// Always `false`: the spec is deterministic input, so retrying cannot help.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

/// Returns `value` with every object's keys sorted, recursively.
///
/// JSON object order is not semantically meaningful, so a canonical form must fix it: two
/// equal `spec` documents must hash identically no matter how a serializer happened to order
/// their keys (and no matter whether `serde_json` was built with `preserve_order`).
#[must_use]
pub fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                if let Some(child) = map.get(key) {
                    sorted.insert(key.clone(), canonical_value(child));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}

/// Compact canonical JSON of `value` (sorted keys, no insignificant whitespace).
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    canonical_value(value).to_string()
}

/// Computes `sha256(canonical_json(spec.source, spec.destination))`.
///
/// The hash deliberately covers `spec.destination` as well: moving an `Application` to another
/// namespace changes what has to be applied even when the repository, revision, and path are
/// untouched.
///
/// # Errors
///
/// [`SourceSpecHashError`] when `spec.source`/`spec.destination` cannot be serialized.
pub fn source_spec_hash(spec: &ApplicationSpec) -> Result<String, SourceSpecHashError> {
    let source = serde_json::to_value(&spec.source).map_err(|err| SourceSpecHashError {
        message: err.to_string(),
    })?;
    let destination =
        serde_json::to_value(&spec.destination).map_err(|err| SourceSpecHashError {
            message: err.to_string(),
        })?;

    // A fixed, sorted root object: canonical_json sorts it again, but building it explicitly
    // keeps the hashed document shape obvious and stable if this ever grows a field.
    let mut root: BTreeMap<&str, Value> = BTreeMap::new();
    root.insert("destination", destination);
    root.insert("source", source);
    // `T20.1`: a multi-source `Application` additionally hashes its `spec.sources` list, so editing
    // a values repository's `targetRevision`/`path`/`tag` (or reordering the list) triggers a sync
    // under `selfHeal: false` even before the source list resolves to different revisions. The key is
    // **absent** for a single-source `Application`, which keeps every pre-`T20.1` spec hash — and
    // therefore every stored `status.sync.lastSyncedSpecHash` — byte-identical across the upgrade.
    if !spec.sources.is_empty() {
        let sources = serde_json::to_value(&spec.sources).map_err(|err| SourceSpecHashError {
            message: err.to_string(),
        })?;
        root.insert("sources", sources);
    }

    let mut object = Map::new();
    for (key, value) in root {
        object.insert(key.to_owned(), value);
    }
    Ok(sha256::hex_digest(
        canonical_json(&Value::Object(object)).as_bytes(),
    ))
}

/// Returns the `(last_synced_revision, last_synced_spec_hash)` pair recorded in `status`.
fn last_synced(app: &Application) -> (Option<&str>, Option<&str>) {
    let sync = app.status.as_ref().and_then(|status| status.sync.as_ref());
    (
        sync.and_then(|state| state.last_synced_revision.as_deref()),
        sync.and_then(|state| state.last_synced_spec_hash.as_deref()),
    )
}

/// The deployed governance verdict on *when* this pass may sync (`T17.4`).
///
/// The engine's window evaluation
/// ([`SyncWindowVerdict`](crate::policy::sync_windows::SyncWindowVerdict)) is reduced to this
/// two-state gate so the decision gate stays clock-free: the caller injects the verdict it computed
/// from its own `now`, exactly as it injects `manual_op`.
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, Default,
)]
#[serde(rename_all = "camelCase")]
pub enum SyncWindowGate {
    /// No window blocks this pass (also the verdict of a project with no windows).
    #[default]
    Allow,
    /// A window blocks it. `manual_override` is `true` only when **every** blocking window sets
    /// `manualSync: true`, in which case a `Manual` trigger is still honoured.
    Deny { manual_override: bool },
}

impl SyncWindowGate {
    /// Builds the gate from a window verdict.
    #[must_use]
    pub fn from_verdict(verdict: &crate::policy::SyncWindowVerdict) -> Self {
        match verdict.denial() {
            None => Self::Allow,
            Some(denial) => Self::Deny {
                manual_override: denial.allows_manual(),
            },
        }
    }

    /// Whether a `Manual` trigger may ignore the window.
    #[must_use]
    pub const fn allows_manual(self) -> bool {
        match self {
            Self::Allow => true,
            Self::Deny { manual_override } => manual_override,
        }
    }

    /// Whether the gate blocks an automated sync.
    #[must_use]
    pub const fn is_denied(self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

impl fmt::Display for SyncWindowGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny { manual_override } => {
                write!(f, "deny (manual override: {manual_override})")
            }
        }
    }
}

/// Decides whether this reconcile should apply the desired set.
///
/// The order of the checks is the specification, not an implementation detail:
///
/// 1. a `Deny` sync window blocks the pass — including a manual one, unless every blocking window
///    sets `manualSync: true` (`T17.4`),
/// 2. a manual operation always executes (it bypasses every sync *policy*),
/// 3. `automated: None` never executes automatically,
/// 4. `selfHeal: false` executes **only** on a source change (revision or spec hash),
/// 5. `selfHeal: true` executes on a source change, then on drift, then on a prune-eligible
///    orphan.
///
/// `manual_op` is the caller's verdict on `ferriscd.io/operation`/CLI/API requests; this
/// function never reads annotations itself (that is the controller's job in `T07.5`). `window` is
/// the caller's verdict on `AppProject.spec.syncWindows`, evaluated at the caller's `now`: this
/// function never reads a clock, so a blocked pass is reproducible in a unit test.
#[must_use]
pub fn should_sync(
    app: &Application,
    resolved_sha: &str,
    source_spec_hash: &str,
    diff_summary: &DiffSummary,
    manual_op: bool,
    window: SyncWindowGate,
) -> SyncDecision {
    // `T17.4` trap guard: a blocked window wins over *everything*, including a manual request,
    // unless the project explicitly opted that window into manual override. Automated triggers are
    // never overridden (`window.allows_manual()` is only consulted together with `manual_op`).
    if window.is_denied() && !(manual_op && window.allows_manual()) {
        return SyncDecision::Skip(SkipReason::SyncWindowDenied);
    }

    if manual_op {
        return SyncDecision::Execute(SyncTrigger::Manual);
    }

    let Some(automated) = app
        .spec
        .sync_policy
        .as_ref()
        .and_then(|policy| policy.automated.as_ref())
    else {
        // Manual-only: report drift, never apply it.
        return SyncDecision::Skip(SkipReason::AutomatedDisabled);
    };

    // Finding H7: a `spec.source`/`spec.destination` edit with an unchanged commit SHA must
    // still be synced, so the pair (revision, spec hash) is compared, not just the revision.
    let (last_revision, last_spec_hash) = last_synced(app);
    let source_changed =
        (Some(resolved_sha), Some(source_spec_hash)) != (last_revision, last_spec_hash);

    if !automated.self_heal {
        return if source_changed {
            SyncDecision::Execute(SyncTrigger::SourceChanged)
        } else {
            SyncDecision::Skip(SkipReason::SelfHealDisabled)
        };
    }

    if source_changed {
        return SyncDecision::Execute(SyncTrigger::SourceChanged);
    }
    if diff_summary.has_drift() {
        return SyncDecision::Execute(SyncTrigger::DriftDetected);
    }
    if automated.prune && diff_summary.has_orphans() {
        return SyncDecision::Execute(SyncTrigger::PruneRequired);
    }
    SyncDecision::Skip(SkipReason::AlreadySynced)
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::{
        ApplicationStatus, AutomatedSyncPolicy, DestinationSpec, GitSourceSpec, RendererSpec,
        SourceSpec, SyncPolicy, SyncState, SyncStatus,
    };
    use serde_json::json;

    use super::*;
    use crate::diff::types::{DiffStatus, ResourceDiff};
    use crate::manifest::ResourceKey;

    /// Every pre-`T17.4` test exercises the gate with **no** sync window: the shim keeps those
    /// truth tables unchanged, and the window cases call `super::should_sync` explicitly.
    fn should_sync(
        app: &Application,
        resolved_sha: &str,
        source_spec_hash: &str,
        diff_summary: &DiffSummary,
        manual_op: bool,
    ) -> SyncDecision {
        super::should_sync(
            app,
            resolved_sha,
            source_spec_hash,
            diff_summary,
            manual_op,
            SyncWindowGate::Allow,
        )
    }

    fn spec() -> ApplicationSpec {
        ApplicationSpec {
            project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: Some(SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "main".to_owned(),
                    path: "deploy/production".to_owned(),
                }),
                oci: None,
                renderer: RendererSpec::default(),
            }),
            sources: Vec::new(),
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: None,
            ignore_differences: Vec::new(),
            requeue_after_seconds: 180,
            revision_history_limit: 10,
        }
    }

    fn app_with(
        automated: Option<AutomatedSyncPolicy>,
        last_synced: Option<(&str, &str)>,
    ) -> Application {
        let mut spec = spec();
        spec.sync_policy = automated.map(|automated| SyncPolicy {
            automated: Some(automated),
            ..SyncPolicy::default()
        });
        let mut app = Application::new("demo", spec);
        app.metadata.namespace = Some("ferriscd-system".to_owned());
        if let Some((revision, hash)) = last_synced {
            let mut sync = SyncState::new(SyncStatus::Synced, Some(revision.to_owned()));
            sync.last_synced_revision = Some(revision.to_owned());
            sync.last_synced_spec_hash = Some(hash.to_owned());
            app.status = Some(ApplicationStatus {
                sync: Some(sync),
                ..ApplicationStatus::default()
            });
        }
        app
    }

    fn policy(self_heal: bool, prune: bool) -> AutomatedSyncPolicy {
        AutomatedSyncPolicy { prune, self_heal }
    }

    fn key(kind: &str, name: &str) -> ResourceKey {
        ResourceKey::new("apps", kind, Some("payments".to_owned()), name)
    }

    fn summary(out_of_sync: usize, missing: usize, orphaned: usize) -> DiffSummary {
        let mut diffs = Vec::new();
        for index in 0..out_of_sync {
            diffs.push(ResourceDiff::conflicted(
                key("Deployment", &format!("oos{index}")),
                Vec::new(),
            ));
        }
        for index in 0..missing {
            diffs.push(ResourceDiff::missing(key(
                "Service",
                &format!("missing{index}"),
            )));
        }
        for index in 0..orphaned {
            diffs.push(ResourceDiff::orphaned(key(
                "ConfigMap",
                &format!("orphan{index}"),
            )));
        }
        diffs.push(ResourceDiff::assemble(
            key("Deployment", "synced"),
            DiffStatus::Synced,
            Vec::new(),
            Vec::new(),
            false,
        ));
        DiffSummary::from_diffs(&diffs)
    }

    const SHA: &str = "8f3a1c2d4e5f60718293a4b5c6d7e8f901234567";
    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const OTHER_HASH: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    /// One `spec` mutation, named for the assertion message.
    type SpecMutation = (&'static str, Box<dyn Fn(&mut ApplicationSpec)>);

    // ------------------------------------------------------------------
    // Manual operations and automated: None
    // ------------------------------------------------------------------

    #[test]
    fn a_manual_operation_always_executes() {
        let policies = [
            None,
            Some(policy(false, false)),
            Some(policy(true, false)),
            Some(policy(true, true)),
        ];
        let diff = summary(0, 0, 0);
        for automated in policies {
            // Even with an unchanged source and zero drift.
            let app = app_with(automated, Some((SHA, HASH)));
            assert_eq!(
                should_sync(&app, SHA, HASH, &diff, true),
                SyncDecision::Execute(SyncTrigger::Manual),
                "a manual operation bypasses every policy (automated: {automated:?})"
            );
        }
    }

    #[test]
    fn automated_disabled_never_executes_automatically() {
        // No `syncPolicy` at all, and a `syncPolicy` without `automated`.
        let no_policy = app_with(None, Some((SHA, HASH)));
        let no_automated = {
            let mut app = app_with(None, Some((SHA, HASH)));
            app.spec.sync_policy = Some(SyncPolicy::default());
            app
        };

        for app in [no_policy, no_automated] {
            for diff in [summary(0, 0, 0), summary(3, 2, 1), summary(0, 0, 5)] {
                // Drift, orphans, and a changed source are all reported but not applied.
                assert_eq!(
                    should_sync(&app, "different-sha", OTHER_HASH, &diff, false),
                    SyncDecision::Skip(SkipReason::AutomatedDisabled)
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // selfHeal: false — source-only sync
    // ------------------------------------------------------------------

    #[test]
    fn self_heal_false_truth_table() {
        // (last revision, last hash) x (resolved sha, hash) => source changed?
        let cases = [
            (Some((SHA, HASH)), SHA, HASH, false),
            (Some((SHA, HASH)), "other-sha", HASH, true),
            (Some((SHA, HASH)), SHA, OTHER_HASH, true),
            (Some((SHA, HASH)), "other-sha", OTHER_HASH, true),
            (None, SHA, HASH, true),
        ];

        for (last, resolved, hash, expected_changed) in cases {
            for diff in [summary(0, 0, 0), summary(4, 4, 4)] {
                let app = app_with(Some(policy(false, false)), last);
                let decision = should_sync(&app, resolved, hash, &diff, false);
                if expected_changed {
                    assert_eq!(
                        decision,
                        SyncDecision::Execute(SyncTrigger::SourceChanged),
                        "last={last:?} resolved={resolved} hash={hash}"
                    );
                } else {
                    assert_eq!(
                        decision,
                        SyncDecision::Skip(SkipReason::SelfHealDisabled),
                        "drift must NOT be applied when selfHeal is false"
                    );
                }
            }
        }
    }

    #[test]
    fn self_heal_false_ignores_drift_and_orphans() {
        let app = app_with(Some(policy(false, true)), Some((SHA, HASH)));
        for diff in [summary(9, 0, 0), summary(0, 9, 0), summary(0, 0, 9)] {
            assert_eq!(
                should_sync(&app, SHA, HASH, &diff, false),
                SyncDecision::Skip(SkipReason::SelfHealDisabled)
            );
        }
    }

    // ------------------------------------------------------------------
    // selfHeal: true — drift correction
    // ------------------------------------------------------------------

    #[test]
    fn self_heal_true_truth_table() {
        // (same source?) x (drift?) x (orphans?) x (prune?) => decision
        for source_changed in [false, true] {
            for (out_of_sync, missing) in [(0, 0), (1, 0), (0, 1)] {
                for orphaned in [0, 2] {
                    for prune in [false, true] {
                        let mut app = app_with(Some(policy(true, prune)), Some((SHA, HASH)));
                        let diff = summary(out_of_sync, missing, orphaned);
                        let resolved = if source_changed { "new-sha" } else { SHA };
                        let hash = if source_changed { OTHER_HASH } else { HASH };

                        let expected = if source_changed {
                            SyncDecision::Execute(SyncTrigger::SourceChanged)
                        } else if out_of_sync + missing > 0 {
                            SyncDecision::Execute(SyncTrigger::DriftDetected)
                        } else if prune && orphaned > 0 {
                            SyncDecision::Execute(SyncTrigger::PruneRequired)
                        } else {
                            SyncDecision::Skip(SkipReason::AlreadySynced)
                        };

                        assert_eq!(
                            should_sync(&app, resolved, hash, &diff, false),
                            expected,
                            "source_changed={source_changed} out_of_sync={out_of_sync} \
                             missing={missing} orphaned={orphaned} prune={prune}"
                        );

                        // The same truth table with an explicit `lastSyncedRevision` marker.
                        app.status = None;
                        assert_eq!(
                            should_sync(&app, resolved, hash, &diff, false),
                            SyncDecision::Execute(SyncTrigger::SourceChanged),
                            "a never-synced application must always sync"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn self_heal_true_never_prunes_without_prune_enabled() {
        let app = app_with(Some(policy(true, false)), Some((SHA, HASH)));
        let diff = summary(0, 0, 3);
        assert_eq!(
            should_sync(&app, SHA, HASH, &diff, false),
            SyncDecision::Skip(SkipReason::AlreadySynced),
            "orphans alone must not trigger a sync when prune is disabled"
        );
    }

    /// Finding M4: an ownership conflict must not make `selfHeal: true` execute forever.
    ///
    /// The object belongs to another `Application`, so no apply can resolve it; the gate skips
    /// (the conflict is still reported in `status`, which stays `OutOfSync`).
    #[test]
    fn an_ownership_conflict_is_terminal_and_never_self_healed() {
        let app = app_with(Some(policy(true, false)), Some((SHA, HASH)));
        let conflict =
            ResourceDiff::ownership_conflict(key("Secret", "creds"), "ferriscd-system/other");
        let diff = DiffSummary::from_diffs([&conflict]);
        assert!(!diff.has_drift());
        assert!(diff.has_ownership_conflicts());
        assert_eq!(
            diff.sync_status(),
            ferriscd_crd::status::SyncStatus::OutOfSync
        );
        assert_eq!(
            should_sync(&app, SHA, HASH, &diff, false),
            SyncDecision::Skip(SkipReason::AlreadySynced),
            "an unfixable ownership conflict must not trigger an apply loop"
        );
        // A manual operation can still be requested (it bypasses every policy), and a source
        // change still syncs — only the endless drift-triggered loop is gone.
        assert_eq!(
            should_sync(&app, SHA, HASH, &diff, true),
            SyncDecision::Execute(SyncTrigger::Manual)
        );
        assert_eq!(
            should_sync(&app, "new-sha", HASH, &diff, false),
            SyncDecision::Execute(SyncTrigger::SourceChanged)
        );
    }

    #[test]
    fn a_synced_application_skips_everything() {
        let app = app_with(Some(policy(true, true)), Some((SHA, HASH)));
        let diff = summary(0, 0, 0);
        assert_eq!(
            should_sync(&app, SHA, HASH, &diff, false),
            SyncDecision::Skip(SkipReason::AlreadySynced)
        );
    }

    // ------------------------------------------------------------------
    // source_spec_hash (finding H7)
    // ------------------------------------------------------------------

    /// The headline H7 case: editing `spec.source.git.path` produces no new commit, so the
    /// revision is identical — and the sync must happen anyway when `selfHeal: false`.
    #[test]
    fn a_git_path_edit_with_an_unchanged_sha_triggers_a_sync() {
        let before = spec();
        let mut after = spec();
        after
            .source
            .as_mut()
            .expect("source")
            .git
            .as_mut()
            .expect("git source")
            .path = "deploy/staging".to_owned();

        let before_hash = source_spec_hash(&before).expect("hash");
        let after_hash = source_spec_hash(&after).expect("hash");
        assert_ne!(
            before_hash, after_hash,
            "a different spec.source.git.path must change the hash"
        );

        let mut app = app_with(Some(policy(false, false)), None);
        app.spec.source = after.source;

        // Same commit SHA as the last sync, but a different spec hash: execute.
        let decision = should_sync(&app, SHA, &after_hash, &summary(0, 0, 0), false);
        assert_eq!(decision, SyncDecision::Execute(SyncTrigger::SourceChanged));

        // A reconcile that persisted the new hash converges back to skip.
        app.status = Some(ApplicationStatus {
            sync: Some({
                let mut sync = SyncState::new(SyncStatus::Synced, Some(SHA.to_owned()));
                sync.last_synced_revision = Some(SHA.to_owned());
                sync.last_synced_spec_hash = Some(after_hash.clone());
                sync
            }),
            ..ApplicationStatus::default()
        });
        assert_eq!(
            should_sync(&app, SHA, &after_hash, &summary(0, 0, 0), false),
            SyncDecision::Skip(SkipReason::SelfHealDisabled)
        );
        // Sanity: the *old* hash is what a stale status would have recorded, and it differs.
        assert_ne!(before_hash, after_hash);
    }

    /// **`T18.4` acceptance criterion.** Editing `spec.source.oci.tag`, `.digest`, or `.path`
    /// changes `source_spec_hash`, so under `selfHeal: false` the pass executes even though the
    /// resolved digest is unchanged (the tag→digest resolution is *not* what the gate keys on).
    #[test]
    fn an_oci_tag_digest_or_path_edit_changes_the_spec_hash_and_triggers_a_sync() {
        const DIGEST: &str =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let oci_spec = || {
            let mut spec = spec();
            let source = spec.source.as_mut().expect("spec.source");
            source.git = None;
            source.oci = Some(ferriscd_crd::OciSourceSpec {
                url: "oci://ghcr.io/example/payments".to_owned(),
                tag: Some("1.4.2".to_owned()),
                digest: None,
                path: "charts/api".to_owned(),
            });
            spec
        };
        let base = source_spec_hash(&oci_spec()).expect("hash");

        // A `fn` pointer (not `Box<dyn Fn>`) so the table stays a plain array of non-capturing
        // mutators — `DIGEST` is a `const`, so nothing is captured.
        type Mutator = fn(&mut ferriscd_crd::OciSourceSpec);
        let mutations: Vec<(&str, Mutator)> = vec![
            ("tag", |oci| oci.tag = Some("1.5.0".to_owned())),
            ("digest", |oci| oci.digest = Some(DIGEST.to_owned())),
            ("path", |oci| oci.path = "charts/web".to_owned()),
            ("url", |oci| {
                oci.url = "oci://ghcr.io/example/billing".to_owned()
            }),
        ];
        for (field, mutate) in mutations {
            let mut mutated = oci_spec();
            mutate(
                mutated
                    .source
                    .as_mut()
                    .expect("spec.source")
                    .oci
                    .as_mut()
                    .expect("oci source"),
            );
            assert_ne!(
                source_spec_hash(&mutated).expect("hash"),
                base,
                "the hash must cover spec.source.oci.{field}"
            );
        }

        // Deterministic, like the Git half.
        assert_eq!(source_spec_hash(&oci_spec()).expect("hash"), base);

        // The gate: an unchanged revision with an edited tag executes under `selfHeal: false`.
        let mut app = app_with(Some(policy(false, false)), None);
        app.spec.source = oci_spec().source;
        let mut edited = app.clone();
        edited
            .spec
            .source
            .as_mut()
            .expect("spec.source")
            .oci
            .as_mut()
            .expect("oci")
            .tag = Some("1.5.0".to_owned());
        let edited_hash = source_spec_hash(&edited.spec).expect("hash");

        app.status = Some(ApplicationStatus {
            sync: Some({
                let mut sync = SyncState::new(SyncStatus::Synced, Some(DIGEST.to_owned()));
                sync.last_synced_revision = Some(DIGEST.to_owned());
                sync.last_synced_spec_hash = Some(base.clone());
                sync
            }),
            ..ApplicationStatus::default()
        });
        assert_eq!(
            should_sync(&app, DIGEST, &base, &summary(0, 0, 0), false),
            SyncDecision::Skip(SkipReason::SelfHealDisabled),
            "an unchanged digest and an unchanged spec must not re-sync"
        );
        assert_eq!(
            should_sync(&app, DIGEST, &edited_hash, &summary(0, 0, 0), false),
            SyncDecision::Execute(SyncTrigger::SourceChanged),
            "editing the tag must trigger a sync even though no manifest moved yet"
        );
    }

    #[test]
    fn a_status_predating_the_spec_hash_triggers_one_sync() {
        // Treating the missing hash as "unchanged" would silently ignore the next spec edit, so
        // the gate must sync once and persist the hash.
        let mut app = app_with(Some(policy(false, false)), None);
        let mut sync = SyncState::new(SyncStatus::Synced, Some(SHA.to_owned()));
        sync.last_synced_revision = Some(SHA.to_owned());
        assert!(sync.last_synced_spec_hash.is_none());
        app.status = Some(ApplicationStatus {
            sync: Some(sync),
            ..ApplicationStatus::default()
        });

        assert_eq!(
            should_sync(&app, SHA, HASH, &summary(0, 0, 0), false),
            SyncDecision::Execute(SyncTrigger::SourceChanged)
        );
    }

    #[test]
    fn the_spec_hash_is_deterministic_and_covers_the_destination() {
        let base = spec();
        let hash = source_spec_hash(&base).expect("hash");

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        for _ in 0..3 {
            assert_eq!(source_spec_hash(&spec()).expect("hash"), hash);
        }

        let mutations: Vec<SpecMutation> = vec![
            (
                "repoURL",
                Box::new(|spec: &mut ApplicationSpec| {
                    spec.source
                        .as_mut()
                        .expect("spec.source")
                        .git
                        .as_mut()
                        .expect("git source")
                        .repo_url = "https://example.com/other.git".to_owned();
                }),
            ),
            (
                "targetRevision",
                Box::new(|spec: &mut ApplicationSpec| {
                    spec.source
                        .as_mut()
                        .expect("spec.source")
                        .git
                        .as_mut()
                        .expect("git source")
                        .target_revision = "release".to_owned();
                }),
            ),
            (
                "path",
                Box::new(|spec: &mut ApplicationSpec| {
                    spec.source
                        .as_mut()
                        .expect("spec.source")
                        .git
                        .as_mut()
                        .expect("git source")
                        .path = String::new();
                }),
            ),
            (
                "renderer",
                Box::new(|spec: &mut ApplicationSpec| {
                    spec.source.as_mut().expect("spec.source").renderer =
                        RendererSpec::Kustomize(Default::default());
                }),
            ),
            (
                "destination.namespace",
                Box::new(|spec: &mut ApplicationSpec| {
                    spec.destination.namespace = "billing".to_owned();
                }),
            ),
            (
                "destination.cluster",
                Box::new(|spec: &mut ApplicationSpec| {
                    spec.destination.cluster = "remote".to_owned();
                }),
            ),
        ];

        for (field, mutate) in mutations {
            let mut mutated = spec();
            mutate(&mut mutated);
            assert_ne!(
                source_spec_hash(&mutated).expect("hash"),
                hash,
                "the hash must cover {field}"
            );
        }
    }

    #[test]
    fn the_spec_hash_matches_an_independently_computed_sha256() {
        // The exact canonical document `source_spec_hash` hashes for `spec()`. The digest below
        // was computed outside this crate:
        //   python3 -c 'hashlib.sha256(<document>.encode()).hexdigest()'
        // which pins both the canonical form (keys, `repoURL`, defaulted renderer) and the
        // SHA-256 implementation.
        const EXPECTED_DOCUMENT: &str = r#"{"destination":{"cluster":"in-cluster","namespace":"payments"},"source":{"git":{"path":"deploy/production","repoURL":"https://example.com/repo.git","targetRevision":"main"},"renderer":{"auto":{}}}}"#;

        let spec = spec();
        let document = canonical_json(&json!({
            "destination": serde_json::to_value(&spec.destination).expect("destination json"),
            "source": serde_json::to_value(&spec.source).expect("source json"),
        }));
        assert_eq!(document, EXPECTED_DOCUMENT);
        assert_eq!(
            source_spec_hash(&spec).expect("hash"),
            "8c7a6044307e4e73e8a90c4c6157e03758bb7799e712a904689c118f310bd7e4"
        );
    }

    #[test]
    fn canonical_json_sorts_object_keys_recursively() {
        let left = json!({ "b": 1, "a": { "y": [ 1, { "q": 2, "p": 3 } ], "x": 0 } });
        let right = json!({ "a": { "x": 0, "y": [ 1, { "p": 3, "q": 2 } ] }, "b": 1 });
        assert_eq!(canonical_json(&left), canonical_json(&right));
        assert_eq!(
            canonical_json(&left),
            r#"{"a":{"x":0,"y":[1,{"p":3,"q":2}]},"b":1}"#
        );
        assert_eq!(canonical_json(&json!(null)), "null");
        assert_eq!(canonical_json(&json!([true, "s"])), r#"[true,"s"]"#);
    }

    // ------------------------------------------------------------------
    // Sync windows (T17.4)
    // ------------------------------------------------------------------

    /// A blocked window stops **every** automated trigger, whatever the drift verdict is.
    #[test]
    fn a_deny_window_blocks_every_automated_trigger() {
        let denied = SyncWindowGate::Deny {
            manual_override: false,
        };
        assert!(denied.is_denied());
        assert!(!denied.allows_manual());

        // `automated: None`, `selfHeal: false`, and `selfHeal: true` all skip identically, and the
        // reason is the window — never `AutomatedDisabled`/`SelfHealDisabled` — so the operator sees
        // governance rather than a policy they did not change.
        for automated in [None, Some(policy(false, false)), Some(policy(true, true))] {
            for diff in [summary(0, 0, 0), summary(3, 2, 1)] {
                for (resolved, hash) in [(SHA, HASH), ("new-sha", OTHER_HASH)] {
                    let app = app_with(automated, Some((SHA, HASH)));
                    assert_eq!(
                        super::should_sync(&app, resolved, hash, &diff, false, denied),
                        SyncDecision::Skip(SkipReason::SyncWindowDenied),
                        "a deny window must block even a source change"
                    );
                }
            }
        }
        // A never-synced application is blocked too (the window is not "wait for the first sync").
        let fresh = app_with(Some(policy(true, true)), None);
        assert_eq!(
            super::should_sync(&fresh, SHA, HASH, &summary(5, 5, 5), false, denied),
            SyncDecision::Skip(SkipReason::SyncWindowDenied)
        );
    }

    /// `manualSync: true` overrides only a **manual** trigger — never an automated one.
    #[test]
    fn a_manual_override_applies_only_to_the_manual_trigger() {
        let overridable = SyncWindowGate::Deny {
            manual_override: true,
        };
        assert!(overridable.allows_manual());
        assert!(overridable.is_denied(), "the gate is still a denial");

        let app = app_with(Some(policy(true, true)), Some((SHA, HASH)));
        assert_eq!(
            super::should_sync(&app, SHA, HASH, &summary(0, 0, 0), true, overridable),
            SyncDecision::Execute(SyncTrigger::Manual),
            "manualSync: true lets a human break glass"
        );
        // The same app, same window, automated trigger: still skipped. The override is not a
        // self-heal switch.
        for diff in [summary(0, 0, 0), summary(4, 0, 0)] {
            assert_eq!(
                super::should_sync(&app, SHA, HASH, &diff, false, overridable),
                SyncDecision::Skip(SkipReason::SyncWindowDenied)
            );
        }
        // ...and a source change does not sneak through either.
        assert_eq!(
            super::should_sync(
                &app,
                "new-sha",
                OTHER_HASH,
                &summary(0, 0, 0),
                false,
                overridable
            ),
            SyncDecision::Skip(SkipReason::SyncWindowDenied)
        );

        // Without the override, even a manual request is refused.
        let strict = SyncWindowGate::Deny {
            manual_override: false,
        };
        assert_eq!(
            super::should_sync(&app, SHA, HASH, &summary(0, 0, 0), true, strict),
            SyncDecision::Skip(SkipReason::SyncWindowDenied)
        );

        // An allowing gate changes nothing about the pre-existing truth table.
        for manual in [false, true] {
            let expected = if manual {
                SyncDecision::Execute(SyncTrigger::Manual)
            } else {
                SyncDecision::Skip(SkipReason::SelfHealDisabled)
            };
            let source_only = app_with(Some(policy(false, false)), Some((SHA, HASH)));
            assert_eq!(
                super::should_sync(
                    &source_only,
                    SHA,
                    HASH,
                    &summary(0, 0, 0),
                    manual,
                    SyncWindowGate::Allow
                ),
                expected
            );
        }
    }

    /// The gate is derived from the engine's verdict, so the two can never disagree.
    #[test]
    fn the_gate_mirrors_the_window_verdict() {
        use ferriscd_crd::{SyncWindow, SyncWindowKind};

        use crate::policy::{SyncWindowSet, SyncWindowTarget};

        fn verdict_at(windows: &[SyncWindow], now: &str) -> crate::policy::SyncWindowVerdict {
            let now = now.parse().expect("test timestamp");
            SyncWindowSet::compile(windows).evaluate(
                now,
                &SyncWindowTarget::new("payments-api", "ferriscd-system", "in-cluster"),
            )
        }

        // (No windows) → Allow.
        assert_eq!(
            SyncWindowGate::from_verdict(&verdict_at(&[], "2026-01-07T12:00:00Z")),
            SyncWindowGate::Allow
        );
        // (Active deny, no manualSync) → Deny, no override.
        let blocking = SyncWindow {
            kind: SyncWindowKind::Deny,
            schedule: "0 0 * * *".to_owned(),
            duration: "24h".to_owned(),
            time_zone: None,
            applications: Vec::new(),
            namespaces: Vec::new(),
            clusters: Vec::new(),
            manual_sync: false,
        };
        assert_eq!(
            SyncWindowGate::from_verdict(&verdict_at(
                std::slice::from_ref(&blocking),
                "2026-01-07T12:00:00Z"
            )),
            SyncWindowGate::Deny {
                manual_override: false
            }
        );
        let mut overridable = blocking;
        overridable.manual_sync = true;
        assert_eq!(
            SyncWindowGate::from_verdict(&verdict_at(&[overridable], "2026-01-07T12:00:00Z")),
            SyncWindowGate::Deny {
                manual_override: true
            }
        );
        assert_eq!(SyncWindowGate::default(), SyncWindowGate::Allow);
        assert_eq!(SyncWindowGate::Allow.to_string(), "allow");
        assert_eq!(
            SyncWindowGate::Deny {
                manual_override: false
            }
            .to_string(),
            "deny (manual override: false)"
        );
        assert_eq!(
            serde_json::to_value(SkipReason::SyncWindowDenied).expect("serialize"),
            json!("syncWindowDenied")
        );
        assert_eq!(
            SkipReason::SyncWindowDenied.to_string(),
            "a sync window of the AppProject blocks this sync right now"
        );
    }

    #[test]
    fn decision_helpers_and_wire_names_are_stable() {
        let execute = SyncDecision::Execute(SyncTrigger::DriftDetected);
        assert!(execute.is_execute());
        assert!(!execute.is_skip());
        assert_eq!(execute.trigger(), Some(SyncTrigger::DriftDetected));
        assert_eq!(execute.skip_reason(), None);
        assert_eq!(execute.to_string(), "execute: driftDetected");
        assert_eq!(
            serde_json::to_value(execute).expect("serialize"),
            json!({ "execute": "driftDetected" })
        );

        let skip = SyncDecision::Skip(SkipReason::AutomatedDisabled);
        assert!(skip.is_skip());
        assert_eq!(skip.skip_reason(), Some(SkipReason::AutomatedDisabled));
        assert_eq!(skip.trigger(), None);
        assert_eq!(skip.to_string(), "skip: automated sync is disabled");
        assert_eq!(
            serde_json::to_value(skip).expect("serialize"),
            json!({ "skip": "automatedDisabled" })
        );
        assert_eq!(
            SkipReason::AlreadySynced.to_string(),
            "live state already matches Git"
        );
        assert_eq!(SkipReason::SelfHealDisabled.as_str(), "selfHealDisabled");
        assert_eq!(SyncTrigger::Manual.as_str(), "manual");
        assert_eq!(SyncTrigger::SourceChanged.as_str(), "sourceChanged");
        assert_eq!(SyncTrigger::PruneRequired.as_str(), "pruneRequired");
        assert!(
            !SourceSpecHashError {
                message: "x".to_owned()
            }
            .is_retryable()
        );
    }
}
