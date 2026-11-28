//! Bounded revision history and GitOps-safe rollback decisions (`T10.5`).
//!
//! Two operator needs, one module:
//!
//! 1. **Audit.** Every successful sync appends a `RevisionHistoryEntry` to `status.history`, so an
//!    operator can see *which* commit was deployed and *when*. The list is bounded by
//!    `min(spec.revisionHistoryLimit, 20)` so it can never bloat `/status` (trap T9).
//! 2. **Emergency rollback.** `ferriscd.io/operation: {"rollback":{"id":N}}` redeploys the commit
//!    recorded by history entry `N`. The decision is not just "sync that SHA": a rollback must also
//!    **disable `spec.syncPolicy.automated`** and emit a `Warning` condition, otherwise the very
//!    next reconcile compares live state against `HEAD` and self-heals the rollback away — the
//!    classic GitOps rollback-vs-`selfHeal` fight loop. Git (not `/status`) is the source of truth,
//!    so the operator is told to revert the commit and re-enable automation.
//!
//! Everything here is pure: no client, no clock (`now` is a parameter), no I/O. The controller owns
//! the two impure steps — resolving the pinned SHA into a rendered commit and patching the spec.
//!
//! ```text
//! status.history: [ {id:2, revision:"sha-v2"}, {id:1, revision:"sha-v1"} ]
//! request:        {"rollback":{"id":1}}
//!                 -> RollbackDecision {
//!                        target: { history_id: 1, revision: "sha-v1" },   // pinned commit
//!                        disable_automated_sync: true,
//!                        condition: Warning/AutomatedSyncDisabledByRollback
//!                    }
//! ```

use ferriscd_crd::application::{ApplicationSpec, SourceSpec};
use ferriscd_crd::status::{
    ApplicationStatus, Condition, ConditionStatus, MAX_HISTORY_ENTRIES, OperationPhase,
    OperationState, RevisionHistoryEntry, SourceSummary,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use serde::Deserialize;

use crate::health::truncate_message;

/// Hard cap on `status.history` entries (mirrors [`ferriscd_crd::status::MAX_HISTORY_ENTRIES`]).
pub const MAX_HISTORY: usize = MAX_HISTORY_ENTRIES;

/// Condition type used to surface the rollback warning.
///
/// `metav1.Condition` has no polarity field, so a warning is a `Warning` condition with
/// `status: True`; `kubectl describe` then shows it alongside `Ready`.
pub const CONDITION_WARNING: &str = "Warning";

/// Reason recorded on the [`CONDITION_WARNING`] condition when a rollback disables automation.
pub const REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK: &str = "AutomatedSyncDisabledByRollback";

/// The effective history bound: `min(spec.revisionHistoryLimit, 20)`, never below `1`.
///
/// `revisionHistoryLimit` is validated to `1..=20` by the CRD schema, but a hand-patched spec (or a
/// future schema change) must not be able to produce an unbounded or empty history.
#[must_use]
pub const fn effective_history_limit(revision_history_limit: i32) -> usize {
    if revision_history_limit < 1 {
        1
    } else if (revision_history_limit as usize) > MAX_HISTORY {
        MAX_HISTORY
    } else {
        revision_history_limit as usize
    }
}

/// What a record call did to `status.history`.
///
/// Recording is idempotent per *operation*, not per call (finding M-5): the machine reports
/// `Finished` on every pass until the controller stops requeueing, so "append on every pass" would
/// churn `/status` (and re-trigger watches) for as long as the operation stays terminal. A repeated
/// pass therefore returns [`SyncRecording::AlreadyRecorded`] and writes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncRecording {
    /// The operation just transitioned into `Succeeded`: one entry was appended.
    Appended(RevisionHistoryEntry),
    /// This exact successful deployment is already in `status.history`; nothing changed.
    AlreadyRecorded {
        /// Id of the existing entry that made this pass a no-op.
        id: i64,
    },
    /// The operation is not a finished success, so nothing was recorded.
    NotSucceeded,
}

impl SyncRecording {
    /// Returns whether this call appended the entry (i.e. is the first `Finished` pass).
    #[must_use]
    pub fn is_first(&self) -> bool {
        matches!(self, Self::Appended(_))
    }

    /// The appended entry, if any.
    #[must_use]
    pub fn entry(&self) -> Option<&RevisionHistoryEntry> {
        match self {
            Self::Appended(entry) => Some(entry),
            Self::AlreadyRecorded { .. } | Self::NotSucceeded => None,
        }
    }
}

/// Summarizes `source` for `status.history`, with the **credential-free** URL.
///
/// Finding M-D: `status.history[].sourceSummary` is shipped in `/status` and printed by
/// `kubectl describe`, so it must not publish the credential that may be embedded in a source URL.
/// `SourceSummary::from_source` copies the effective URL verbatim (it lives in `ferriscd-crd`, which
/// deliberately has no shared Git URL grammar), so the one production site that builds a history
/// entry redacts here, per source kind:
///
/// * a Git remote keeps its SCP-style login (`git@github.com:org/repo.git` is not a credential) and
///   loses only `user:token@`/`token@` userinfo — [`redact_repo_url`];
/// * an OCI reference has no SCP-style spelling, so *every* userinfo is a credential —
///   [`redact_oci_url_credentials`], the registry-shaped rule the engine's `repo` module already uses
///   when it refuses a reference.
///
/// Both helpers are the ones the rest of the controller logs through, so a rejected URL, a log line,
/// and a history entry can never disagree about what is safe to print.
fn redacted_source_summary(source: &SourceSpec) -> SourceSummary {
    let mut summary = SourceSummary::from_source(source);
    summary.repo_url = if source.oci_source().is_some() {
        crate::repo::redact_oci_url_credentials(&summary.repo_url)
    } else {
        crate::manifest::redact_repo_url(&summary.repo_url)
    };
    summary
}

/// Appends a successful sync to `status.history` and trims it to the effective bound.
///
/// The new entry gets `id = max(existing ids) + 1` — monotonic even when older entries have been
/// trimmed — is inserted newest-first, and the list is truncated to
/// [`effective_history_limit`]. `revision` is the resolved commit SHA (never `HEAD`), and
/// `source` (when known) is summarized into the entry's `sourceSummary` metadata (finding H4).
///
/// `deployed_at` must be the time the deployment finished — normally
/// `operationState.finishedAt` — because `(revision, deployed_at)` is the idempotency key: a second
/// call with the same pair returns [`SyncRecording::AlreadyRecorded`] instead of appending a
/// duplicate (finding M-5). [`record_operation_success`] derives both from the operation state, so
/// callers should prefer it.
///
/// The truncation itself is delegated to [`ApplicationStatus::push_history`], which enforces the
/// same `clamp(1, MAX_HISTORY_ENTRIES)` bound; a test pins the two together so the documented
/// `min(spec.revisionHistoryLimit, 20)` contract cannot drift from the implementation.
#[must_use]
pub fn record_sync_success(
    status: &mut ApplicationStatus,
    revision: Option<String>,
    source: Option<&SourceSpec>,
    revisions: &[String],
    revision_history_limit: i32,
    deployed_at: Time,
) -> SyncRecording {
    if let Some(latest) = status.history.first()
        && latest.revision == revision
        && latest.deployed_at == deployed_at
    {
        return SyncRecording::AlreadyRecorded { id: latest.id };
    }

    let next_id = status
        .history
        .iter()
        .map(|entry| entry.id)
        .max()
        .map_or(1, |id| id.saturating_add(1));
    let entry = RevisionHistoryEntry::new(next_id, revision, deployed_at)
        .with_source_summary(source.map(redacted_source_summary))
        // `T20.1`: a multi-source deployment records **every** source's revision here (and only
        // here — a single-source deployment leaves the field absent, so a `v1.0` history entry is
        // byte-identical). A rollback reads it back to re-pin the same per-source revisions.
        .with_revisions(revisions.to_vec());
    // `push_history` inserts newest-first and truncates to `clamp(1, MAX_HISTORY_ENTRIES)`.
    status.push_history(entry.clone(), revision_history_limit.max(1));
    SyncRecording::Appended(entry)
}

/// Records the terminal success of `operation`, exactly once, into `status.history`.
///
/// This is the entry point the controller should call once per pass: it refuses a non-`Succeeded`
/// operation ([`SyncRecording::NotSucceeded`]), derives `deployedAt` from
/// `operationState.finishedAt` (falling back to `startedAt` for a hand-written state), and is
/// idempotent, so the repeatedly-observed `Finished` action never appends a second entry.
#[must_use]
pub fn record_operation_success(
    status: &mut ApplicationStatus,
    operation: &OperationState,
    source: Option<&SourceSpec>,
    revisions: &[String],
    revision_history_limit: i32,
) -> SyncRecording {
    if operation.phase != OperationPhase::Succeeded {
        return SyncRecording::NotSucceeded;
    }
    let deployed_at = operation
        .finished_at
        .clone()
        .unwrap_or_else(|| operation.started_at.clone());
    record_sync_success(
        status,
        operation.revision.clone(),
        source,
        revisions,
        revision_history_limit,
        deployed_at,
    )
}

/// The per-source revisions to re-pin when `pinned` names an existing history entry (`T20.1`).
///
/// A rollback of a multi-source `Application` cannot be honoured by pinning one string: the
/// deployment identity is the composite digest (`sha256:<64 hex>` over the ordered list), which no
/// resolver can turn back into per-source revisions. The history entry that identity came from also
/// carries every source's revision (`status.history[].revisions`), so the caller re-pins each source
/// from the recorded list.
///
/// Returns `None` when no entry matches `pinned`, **or** when the matching entry recorded no
/// per-source list (a `v1.0` single-source entry, or one written before `T20.1`). The caller must
/// treat the two cases as it sees fit — a single-source pass can still pin `pinned` directly, while
/// a multi-source one has to refuse rather than hand a composite digest to a Git/OCI resolver
/// (finding H2) — which is why this function reports "not recorded" instead of guessing.
#[must_use]
pub fn recorded_revisions(status: &ApplicationStatus, pinned: &str) -> Option<Vec<String>> {
    status
        .history
        .iter()
        .find(|entry| entry.revision.as_deref() == Some(pinned))
        .filter(|entry| !entry.revisions.is_empty())
        .map(|entry| entry.revisions.clone())
}

/// A parsed rollback request (`{"rollback":{"id":N}}`).
#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RollbackRequest {
    /// History id to redeploy.
    pub id: i64,
}

/// The `ferriscd.io/operation` payload as far as this module cares.
///
/// Unknown top-level keys are ignored so a newer CLI can add operations without breaking an older
/// controller, and a payload without `rollback` is reported as [`RollbackError::NotARollback`]
/// rather than silently ignored.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct OperationPayload {
    #[serde(default)]
    rollback: Option<RollbackRequest>,
}

/// A resolved rollback target: the historical commit to redeploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackTarget {
    /// The history entry id that was requested.
    pub history_id: i64,
    /// The commit SHA recorded for that entry (the pinned revision).
    pub revision: String,
    /// When that revision was originally deployed.
    pub deployed_at: Time,
}

/// The pure decision to perform a rollback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackDecision {
    /// The pinned historical target.
    pub target: RollbackTarget,
    /// Always `true`: a rollback disables `spec.syncPolicy.automated` so `selfHeal` cannot
    /// immediately revert it to `HEAD`. Recorded as data so `/status` shows what the rollback did.
    pub disable_automated_sync: bool,
    /// The `Warning`/`AutomatedSyncDisabledByRollback` condition to persist.
    pub condition: Condition,
}

impl RollbackDecision {
    /// The commit SHA the rollback is pinned to.
    #[must_use]
    pub fn pinned_revision(&self) -> &str {
        &self.target.revision
    }

    /// Disables `spec.syncPolicy.automated`, returning whether the spec changed.
    ///
    /// Idempotent: a second call (or an already manual-only application) returns `false` and writes
    /// nothing, so repeated reconciles never churn the spec.
    pub fn apply_to_spec(&self, spec: &mut ApplicationSpec) -> bool {
        if !self.disable_automated_sync {
            return false;
        }
        disable_automated_sync(spec)
    }
}

/// Removes `spec.syncPolicy.automated`, returning whether anything changed.
pub fn disable_automated_sync(spec: &mut ApplicationSpec) -> bool {
    match spec.sync_policy.as_mut() {
        Some(policy) if policy.automated.is_some() => {
            policy.automated = None;
            true
        }
        // Already manual-only (`syncPolicy` absent, or `automated` already `None`): nothing to do.
        // A missing `syncPolicy` is left absent rather than materialized as an empty struct.
        Some(_) | None => false,
    }
}

/// Removes the `Warning`/`AutomatedSyncDisabledByRollback` condition, returning whether one was
/// removed.
///
/// A rollback disables automation and records the warning so the operator knows the rollback is
/// holding `HEAD` back. Nothing clears it today, so the warning would stay on `kubectl describe`
/// forever, long after Git was fixed — a stale warning that trains operators to ignore warnings.
/// [`clear_rollback_warning_if_automation_reenabled`] is the wiring seam (finding M-4).
pub fn clear_rollback_warning(status: &mut ApplicationStatus) -> bool {
    let before = status.conditions.len();
    status.conditions.retain(|condition| {
        !(condition.type_ == CONDITION_WARNING
            && condition.reason == REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK)
    });
    status.conditions.len() != before
}

/// Clears the rollback warning once the operator has re-enabled `spec.syncPolicy.automated`.
///
/// Re-enabling automation is exactly the action the warning asks for (the operator reverted the
/// commit in Git and turned automation back on), so the warning is removed and the next reconcile
/// proceeds normally. Returns whether a condition was removed; a manual-only application keeps its
/// warning, because then the rollback is still what is holding the revision in place.
pub fn clear_rollback_warning_if_automation_reenabled(
    spec: &ApplicationSpec,
    status: &mut ApplicationStatus,
) -> bool {
    let reenabled = spec
        .sync_policy
        .as_ref()
        .is_some_and(ferriscd_crd::SyncPolicy::is_automated);
    if !reenabled {
        return false;
    }
    clear_rollback_warning(status)
}

/// Parses `ferriscd.io/operation` and requires a rollback request.
///
/// # Errors
///
/// * [`RollbackError::MalformedOperation`] — the annotation is not the documented JSON shape
///   (`{"rollback":{"id":N}}` with an integer `id`).
/// * [`RollbackError::NotARollback`] — valid JSON, but no `rollback` block (e.g. a `sync` request).
pub fn parse_rollback_request(operation: &str) -> Result<RollbackRequest, RollbackError> {
    let payload: OperationPayload =
        serde_json::from_str(operation).map_err(|err| RollbackError::MalformedOperation {
            message: err.to_string(),
        })?;
    payload.rollback.ok_or(RollbackError::NotARollback)
}

/// Looks up the rollback target by history id.
///
/// # Errors
///
/// * [`RollbackError::UnknownHistoryId`] — no entry with that id (listing the known ids, so an
///   operator can correct the annotation without `kubectl get -o yaml`).
/// * [`RollbackError::MissingRevision`] — the entry exists but has no commit SHA to redeploy.
pub fn rollback_target(
    status: &ApplicationStatus,
    id: i64,
) -> Result<RollbackTarget, RollbackError> {
    let entry = status
        .history
        .iter()
        .find(|entry| entry.id == id)
        .ok_or_else(|| RollbackError::UnknownHistoryId {
            id,
            known: status.history.iter().map(|entry| entry.id).collect(),
        })?;

    let revision = entry
        .revision
        .as_deref()
        .map(str::trim)
        .filter(|revision| !revision.is_empty())
        .ok_or(RollbackError::MissingRevision { id })?
        .to_owned();

    Ok(RollbackTarget {
        history_id: entry.id,
        revision,
        deployed_at: entry.deployed_at.clone(),
    })
}

/// Plans a rollback: resolves the target, and returns the decision to persist and act on.
///
/// # Errors
///
/// Propagates [`rollback_target`]'s error.
pub fn plan_rollback(
    status: &ApplicationStatus,
    request: RollbackRequest,
    now: &Time,
) -> Result<RollbackDecision, RollbackError> {
    let target = rollback_target(status, request.id)?;
    let message = truncate_message(&format!(
        "Rollback to history id {} (revision {}) disabled automated sync so self-heal cannot \
         overwrite it; revert the commit in Git and re-enable spec.syncPolicy.automated",
        target.history_id, target.revision
    ));
    let condition = Condition::new(
        CONDITION_WARNING,
        ConditionStatus::True,
        REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK,
        message,
        now.clone(),
    );

    Ok(RollbackDecision {
        target,
        disable_automated_sync: true,
        condition,
    })
}

/// Why a rollback request could not be planned.
///
/// Every variant is terminal: the request and `status.history` are deterministic input, so a retry
/// can never change the answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RollbackError {
    /// `ferriscd.io/operation` is not the documented JSON shape.
    #[error("malformed ferriscd.io/operation annotation: {message}")]
    MalformedOperation {
        /// The underlying serde message.
        message: String,
    },

    /// `ferriscd.io/operation` is valid JSON but carries no `rollback` block.
    #[error(
        "ferriscd.io/operation is not a rollback request; expected \
         {{\"rollback\":{{\"id\":<history id>}}}}"
    )]
    NotARollback,

    /// No `status.history` entry carries the requested id.
    #[error("no status.history entry with id {id}; known ids: {known:?}")]
    UnknownHistoryId {
        /// The requested id.
        id: i64,
        /// The ids that do exist (bounded by the history cap).
        known: Vec<i64>,
    },

    /// The history entry has no commit SHA, so there is nothing to pin.
    #[error("status.history entry {id} has no revision; there is nothing to roll back to")]
    MissingRevision {
        /// The requested id.
        id: i64,
    },
}

impl RollbackError {
    /// Always `false`: the values come from Git and `/status`, never from a transient failure.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use ferriscd_crd::status::{OperationState, SyncState, SyncStatus};
    use ferriscd_crd::{
        Application, AutomatedSyncPolicy, DestinationSpec, GitSourceSpec, RendererSpec, SourceSpec,
        SyncPolicy,
    };

    use super::*;
    use crate::diff::decision::{
        SkipReason, SyncDecision, SyncTrigger, SyncWindowGate, should_sync,
    };
    use crate::diff::types::DiffSummary;

    const SHA_V1: &str = "1111111111111111111111111111111111111111";
    const SHA_V2: &str = "2222222222222222222222222222222222222222";
    const SPEC_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// An automated (`selfHeal: true`), non-pruning application.
    fn app_with_automated(automated: bool) -> Application {
        let spec = ApplicationSpec {
            project: ferriscd_crd::DEFAULT_PROJECT_NAME.to_owned(),
            service_account_name: None,
            source: Some(SourceSpec {
                git: Some(GitSourceSpec {
                    repo_url: "https://example.com/repo.git".to_owned(),
                    target_revision: "main".to_owned(),
                    path: String::new(),
                }),
                oci: None,
                renderer: RendererSpec::default(),
            }),
            sources: Vec::new(),
            destination: DestinationSpec {
                cluster: "in-cluster".to_owned(),
                namespace: "payments".to_owned(),
            },
            sync_policy: Some(SyncPolicy {
                automated: automated.then_some(AutomatedSyncPolicy {
                    prune: false,
                    self_heal: true,
                }),
                ..SyncPolicy::default()
            }),
            ignore_differences: Vec::new(),
            requeue_after_seconds: 180,
            revision_history_limit: 10,
        };
        Application::new("payments", spec)
    }

    /// A diff with one drifted resource (`selfHeal: true` would re-apply).
    fn drift_summary() -> DiffSummary {
        DiffSummary {
            total: 1,
            out_of_sync: 1,
            ..DiffSummary::default()
        }
    }

    fn at(rfc3339: &str) -> Time {
        Time(rfc3339.parse().expect("valid RFC 3339 timestamp"))
    }

    fn entry(id: i64, revision: Option<&str>) -> RevisionHistoryEntry {
        RevisionHistoryEntry::new(id, revision.map(str::to_owned), at("2026-11-24T12:00:00Z"))
    }

    fn status_with(entries: Vec<RevisionHistoryEntry>) -> ApplicationStatus {
        ApplicationStatus {
            history: entries,
            ..ApplicationStatus::default()
        }
    }

    #[test]
    fn successful_syncs_append_history_and_trim_to_the_limit() {
        let mut status = ApplicationStatus::default();
        let limit = 20;

        for index in 0..25 {
            let revision = format!("rev-{index}");
            let recorded = record_sync_success(
                &mut status,
                Some(revision.clone()),
                None,
                &[],
                limit,
                at("2026-11-24T12:00:00Z"),
            );
            let entry = recorded.entry().expect("each new revision is appended");
            assert!(recorded.is_first());
            assert_eq!(entry.id, index + 1, "ids are monotonic");
            assert_eq!(entry.revision.as_deref(), Some(revision.as_str()));
        }

        assert_eq!(status.history.len(), MAX_HISTORY);
        let ids: Vec<i64> = status.history.iter().map(|entry| entry.id).collect();
        assert_eq!(ids, (6..=25).rev().collect::<Vec<_>>());
        assert_eq!(
            status.history[0].revision.as_deref(),
            Some("rev-24"),
            "newest first"
        );
        assert!(status.history.len() <= MAX_HISTORY_ENTRIES);
    }

    #[test]
    fn the_history_limit_is_never_below_one_or_above_twenty() {
        assert_eq!(effective_history_limit(1), 1);
        assert_eq!(effective_history_limit(5), 5);
        assert_eq!(effective_history_limit(20), 20);
        assert_eq!(effective_history_limit(21), 20);
        assert_eq!(effective_history_limit(i32::MAX), 20);
        assert_eq!(effective_history_limit(0), 1);
        assert_eq!(effective_history_limit(-7), 1);

        // Every documented limit really bounds the list.
        for limit in [-1, 0, 1, 3, 10, 20, 25] {
            let mut status = ApplicationStatus::default();
            for index in 0..30 {
                let _ = record_sync_success(
                    &mut status,
                    Some(format!("rev-{index}")),
                    None,
                    &[],
                    limit,
                    at("2026-11-24T12:00:00Z"),
                );
            }
            assert_eq!(
                status.history.len(),
                effective_history_limit(limit),
                "limit {limit}"
            );
            assert!(!status.history.is_empty(), "history never becomes empty");
        }
    }

    #[test]
    fn an_entry_without_a_revision_still_occupies_a_bounded_slot() {
        let mut status = ApplicationStatus::default();
        let recorded =
            record_sync_success(&mut status, None, None, &[], 3, at("2026-11-24T12:00:00Z"));
        let recorded = recorded
            .entry()
            .expect("an unknown revision is still a deployment");
        assert_eq!(recorded.revision, None);
        assert_eq!(status.history.len(), 1);
        assert_eq!(
            rollback_target(&status, recorded.id),
            Err(RollbackError::MissingRevision { id: recorded.id })
        );
    }

    #[test]
    fn ids_stay_monotonic_after_trimming() {
        let mut status = ApplicationStatus::default();
        for index in 0..25 {
            let _ = record_sync_success(
                &mut status,
                Some(format!("rev-{index}")),
                None,
                &[],
                2,
                at("2026-11-24T12:00:00Z"),
            );
        }
        assert_eq!(status.history.len(), 2);
        let ids: Vec<i64> = status.history.iter().map(|entry| entry.id).collect();
        assert_eq!(ids, vec![25, 24], "trimming must not reset the id sequence");
    }

    #[test]
    fn rollback_targets_are_looked_up_by_history_id() {
        let status = status_with(vec![entry(2, Some(SHA_V2)), entry(1, Some(SHA_V1))]);

        let target = rollback_target(&status, 1).expect("history id 1 exists");
        assert_eq!(
            target,
            RollbackTarget {
                history_id: 1,
                revision: SHA_V1.to_owned(),
                deployed_at: at("2026-11-24T12:00:00Z"),
            }
        );
        assert_eq!(rollback_target(&status, 2).expect("id 2").revision, SHA_V2);

        let err = rollback_target(&status, 9).expect_err("unknown id");
        assert_eq!(
            err,
            RollbackError::UnknownHistoryId {
                id: 9,
                known: vec![2, 1]
            }
        );
        assert!(!err.is_retryable());
        let text = err.to_string();
        assert!(text.contains("id 9"), "{text}");
        assert!(
            text.contains("[2, 1]"),
            "the error lists the known ids: {text}"
        );

        // A present-but-blank revision is not a valid target either.
        let blank = status_with(vec![entry(1, Some("   "))]);
        assert_eq!(
            rollback_target(&blank, 1),
            Err(RollbackError::MissingRevision { id: 1 })
        );

        // An empty history reports every id as unknown instead of panicking.
        assert!(matches!(
            rollback_target(&ApplicationStatus::default(), 1),
            Err(RollbackError::UnknownHistoryId { known, .. }) if known.is_empty()
        ));
    }

    #[test]
    fn the_rollback_decision_pins_the_historical_commit_and_disables_automation() {
        let status = status_with(vec![entry(2, Some(SHA_V2)), entry(1, Some(SHA_V1))]);
        let now = at("2026-11-24T12:10:00Z");
        let decision = plan_rollback(&status, RollbackRequest { id: 1 }, &now).expect("rollback");

        assert_eq!(decision.pinned_revision(), SHA_V1);
        assert_eq!(decision.target.history_id, 1);
        assert_ne!(
            decision.pinned_revision(),
            SHA_V2,
            "the rollback must pin history, never HEAD"
        );
        assert!(decision.disable_automated_sync);

        // The warning condition is what tells the operator to revert in Git.
        assert_eq!(decision.condition.type_, CONDITION_WARNING);
        assert_eq!(decision.condition.status, ConditionStatus::True);
        assert_eq!(
            decision.condition.reason,
            REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK
        );
        assert_eq!(decision.condition.last_transition_time, now);
        assert_eq!(decision.condition.observed_generation, None);
        let message = &decision.condition.message;
        assert!(message.contains("history id 1"), "{message}");
        assert!(message.contains(SHA_V1), "{message}");
        assert!(
            message.contains("re-enable spec.syncPolicy.automated"),
            "the operator must be told how to finish the rollback: {message}"
        );
        assert!(
            message.chars().count() <= ferriscd_crd::status::MAX_STATUS_MESSAGE_CHARS + 1,
            "{} chars",
            message.chars().count()
        );

        // Applying the decision to the spec disables automation exactly once.
        let mut spec = app_with_automated(true).spec;
        assert!(
            spec.sync_policy
                .as_ref()
                .is_some_and(|policy| policy.is_automated())
        );
        assert!(
            decision.apply_to_spec(&mut spec),
            "automation must be disabled"
        );
        let policy = spec.sync_policy.as_ref().expect("syncPolicy stays present");
        assert!(policy.automated.is_none());
        assert!(!policy.is_automated());
        assert!(!policy.self_heal_enabled());
        assert!(!decision.apply_to_spec(&mut spec), "idempotent");

        // A manual-only spec is untouched (no empty `syncPolicy` is materialized).
        let mut manual = app_with_automated(false).spec;
        manual.sync_policy = None;
        assert!(!decision.apply_to_spec(&mut manual));
        assert!(manual.sync_policy.is_none());
    }

    /// T10.5 trap guard: without disabling automation the next reconcile self-heals `HEAD` right
    /// back over the rollback. This test drives the real decision gate to prove it does not.
    #[test]
    fn a_planned_rollback_stops_self_heal_from_overwriting_the_pinned_commit() {
        // An automated, self-healing app that last synced SHA_V2, with one drifted resource.
        let mut app = app_with_automated(true);
        let mut sync = SyncState::new(SyncStatus::Synced, Some(SHA_V2.to_owned()));
        sync.last_synced_revision = Some(SHA_V2.to_owned());
        sync.last_synced_spec_hash = Some(SPEC_HASH.to_owned());
        app.status = Some(ApplicationStatus {
            sync: Some(sync),
            ..ApplicationStatus::default()
        });
        let head = SHA_V2;
        let drift = drift_summary();

        // Baseline: the source is unchanged, so self-heal re-applies HEAD on every pass.
        assert_eq!(
            should_sync(&app, head, SPEC_HASH, &drift, false, SyncWindowGate::Allow),
            SyncDecision::Execute(SyncTrigger::DriftDetected)
        );

        let status = status_with(vec![entry(2, Some(SHA_V2)), entry(1, Some(SHA_V1))]);
        let decision = plan_rollback(
            &status,
            RollbackRequest { id: 1 },
            &at("2026-11-24T12:10:00Z"),
        )
        .expect("rollback");

        let mut rolled_back = app.clone();
        assert!(decision.apply_to_spec(&mut rolled_back.spec));
        assert_eq!(
            should_sync(
                &rolled_back,
                head,
                SPEC_HASH,
                &drift,
                false,
                SyncWindowGate::Allow
            ),
            SyncDecision::Skip(SkipReason::AutomatedDisabled),
            "the pinned revision must survive subsequent requeues"
        );

        // A manual operation is still allowed (the rollback itself runs as one).
        assert!(
            should_sync(
                &rolled_back,
                decision.pinned_revision(),
                SPEC_HASH,
                &drift,
                true,
                SyncWindowGate::Allow
            )
            .is_execute()
        );
    }

    #[test]
    fn rollback_requests_parse_from_the_operation_annotation() {
        assert_eq!(
            parse_rollback_request(r#"{"rollback":{"id":3}}"#).expect("valid request"),
            RollbackRequest { id: 3 }
        );
        // Unknown sibling keys are tolerated so a newer CLI cannot break an older controller.
        assert_eq!(
            parse_rollback_request(r#"{"refresh":"abc","rollback":{"id":1}}"#).expect("valid"),
            RollbackRequest { id: 1 }
        );

        for malformed in [
            "",
            "not json",
            "null",
            r#"{"rollback":{"id":"3"}}"#,
            r#"{"rollback":{"id":1.5}}"#,
            r#"{"rollback":{}}"#,
            r#"{"rollback":true}"#,
        ] {
            let err = parse_rollback_request(malformed).expect_err("must be rejected");
            assert!(
                matches!(err, RollbackError::MalformedOperation { .. }),
                "unexpected variant for {malformed:?}: {err:?}"
            );
            assert!(!err.is_retryable());
            assert!(err.to_string().contains("ferriscd.io/operation"), "{err}");
        }

        for not_a_rollback in [r#"{}"#, r#"{"sync":{"revision":"abc"}}"#] {
            assert_eq!(
                parse_rollback_request(not_a_rollback),
                Err(RollbackError::NotARollback),
                "{not_a_rollback}"
            );
        }
        assert!(!RollbackError::NotARollback.is_retryable());
    }

    #[test]
    fn history_and_operation_state_coexist_in_one_status() {
        // Sanity check that a rollback decision does not disturb the operation state that the
        // `T10.1` state machine persists, and vice versa.
        let mut status = record_and_status();
        status.operation_state = Some(OperationState {
            phase: ferriscd_crd::status::OperationPhase::Succeeded,
            sync_phase: Some(ferriscd_crd::status::SyncPhase::Succeeded),
            current_wave: 0,
            phase_started_at: Some(at("2026-11-24T12:00:00Z")),
            revision: Some(SHA_V1.to_owned()),
            active_hooks: Vec::new(),
            metric_gate: None,
            message: Some("sync completed".to_owned()),
            started_at: at("2026-11-24T11:59:00Z"),
            finished_at: Some(at("2026-11-24T12:00:00Z")),
        });
        let decision = plan_rollback(
            &status,
            RollbackRequest { id: 1 },
            &at("2026-11-24T12:05:00Z"),
        )
        .expect("rollback");
        assert_eq!(decision.pinned_revision(), SHA_V1);

        let json = serde_json::to_value(&status).expect("status serializes");
        assert_eq!(json["history"][0]["id"], serde_json::json!(1));
        assert_eq!(
            json["operationState"]["syncPhase"],
            serde_json::json!("Succeeded")
        );
    }

    fn source() -> SourceSpec {
        app_with_automated(false)
            .spec
            .source
            .expect("a single-source Application")
    }

    fn record_and_status() -> ApplicationStatus {
        let mut status = ApplicationStatus::default();
        let _ = record_sync_success(
            &mut status,
            Some(SHA_V1.to_owned()),
            None,
            &[],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        status.sync = Some(SyncState::new(SyncStatus::Synced, Some(SHA_V1.to_owned())));
        status
    }

    #[test]
    fn history_keeps_the_sync_state_revision_untouched() {
        let mut status = record_and_status();
        let before = status.sync.clone();
        let _ = record_sync_success(
            &mut status,
            Some(SHA_V2.to_owned()),
            None,
            &[],
            10,
            at("2026-11-24T12:30:00Z"),
        );
        assert_eq!(
            status.sync, before,
            "recording history must not rewrite sync state"
        );
        assert_eq!(status.history.len(), 2);
        assert_eq!(status.history[0].revision.as_deref(), Some(SHA_V2));
    }

    /// Finding H4: the entry records which source produced the revision, so history stays
    /// self-describing after a `spec.source` edit.
    #[test]
    fn history_entries_record_the_source_summary() {
        let mut status = ApplicationStatus::default();
        let recorded = record_sync_success(
            &mut status,
            Some(SHA_V1.to_owned()),
            Some(&source()),
            &[],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        let entry = recorded.entry().expect("appended");
        let summary = entry
            .source_summary
            .clone()
            .expect("a recorded deployment carries its source");
        assert_eq!(summary.repo_url, "https://example.com/repo.git");
        assert_eq!(summary.path, "");
        assert_eq!(summary.target_revision, "main");
        assert_eq!(summary.renderer, ferriscd_crd::RendererSpec::default());
        assert_eq!(summary, SourceSummary::from_source(&source()));

        // The summary is metadata only: it survives `/status` and never carries manifest content.
        let json = serde_json::to_value(&status).expect("status serializes");
        assert_eq!(
            json["history"][0]["sourceSummary"]["repoURL"],
            serde_json::json!("https://example.com/repo.git")
        );
        assert_eq!(
            json["history"][0]["sourceSummary"]["targetRevision"],
            serde_json::json!("main")
        );

        // Without a source the field is simply absent (older callers, an unknown renderer).
        let mut anonymous = ApplicationStatus::default();
        let recorded = record_sync_success(
            &mut anonymous,
            Some(SHA_V2.to_owned()),
            None,
            &[],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        assert!(recorded.entry().expect("appended").source_summary.is_none());
    }

    /// **`T20.1` finding H2.** The per-source revisions a multi-source rollback re-pins come from
    /// the history entry the composite identity was recorded with — and only from there.
    #[test]
    fn recorded_revisions_are_read_back_from_the_matching_history_entry() {
        const COMPOSITE: &str =
            "sha256:8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";
        let multi = status_with(vec![
            RevisionHistoryEntry::new(2, Some(SHA_V2.to_owned()), at("2026-11-24T13:00:00Z"))
                .with_revisions(vec!["chart-sha-v2".to_owned(), "values-sha-v2".to_owned()]),
            RevisionHistoryEntry::new(1, Some(COMPOSITE.to_owned()), at("2026-11-24T12:00:00Z"))
                .with_revisions(vec!["chart-sha".to_owned(), "values-sha".to_owned()]),
        ]);

        assert_eq!(
            recorded_revisions(&multi, COMPOSITE),
            Some(vec!["chart-sha".to_owned(), "values-sha".to_owned()]),
            "the entry is addressed by the identity it recorded, in declaration order"
        );
        assert_eq!(
            recorded_revisions(&multi, SHA_V2),
            Some(vec!["chart-sha-v2".to_owned(), "values-sha-v2".to_owned()])
        );

        // An entry that recorded no per-source list (a `v1.0` single-source deployment, or one
        // written before `T20.1`) answers `None`: the caller must not guess the per-source split.
        let legacy = status_with(vec![RevisionHistoryEntry::new(
            1,
            Some(SHA_V1.to_owned()),
            at("2026-11-24T12:00:00Z"),
        )]);
        assert_eq!(recorded_revisions(&legacy, SHA_V1), None);

        // A revision no entry names (`HEAD~1`-style pinning, or a rewritten history) answers `None`.
        assert_eq!(recorded_revisions(&multi, "an-unknown-revision"), None);
        assert_eq!(
            recorded_revisions(&ApplicationStatus::default(), COMPOSITE),
            None
        );

        // The recorded list is what a settle actually writes: a multi-source deployment records it
        // in `history[]` and nowhere else, so this round-trips through the same call.
        let mut status = ApplicationStatus::default();
        let recorded = record_sync_success(
            &mut status,
            Some(COMPOSITE.to_owned()),
            None,
            &["chart-sha".to_owned(), "values-sha".to_owned()],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        assert_eq!(
            recorded.entry().expect("appended").revisions,
            vec!["chart-sha".to_owned(), "values-sha".to_owned()]
        );
        assert_eq!(
            recorded_revisions(&status, COMPOSITE),
            Some(vec!["chart-sha".to_owned(), "values-sha".to_owned()])
        );
        // A single-source deployment records no list at all (the `v1.0` shape stays byte-identical).
        let mut single = ApplicationStatus::default();
        let recorded = record_sync_success(
            &mut single,
            Some(SHA_V1.to_owned()),
            None,
            &[],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        assert!(recorded.entry().expect("appended").revisions.is_empty());
        assert_eq!(recorded_revisions(&single, SHA_V1), None);
    }

    /// **Finding M-D (`T18.4`).** `status.history[].sourceSummary.repoURL` is shipped in `/status`
    /// and printed by `kubectl describe`, so an embedded credential must be redacted — the T18.3
    /// build pinned the leaky shape on purpose, and this is the flip.
    ///
    /// The rule is per source kind: a Git remote keeps its SCP-style login and loses only real
    /// userinfo, while an OCI reference (which has no SCP-style spelling) loses every `@` userinfo.
    #[test]
    fn a_history_source_summary_redacts_an_embedded_credential() {
        const SECRET: &str = "ghp-t0ken-in-the-remote";
        let remote = format!("https://user:{SECRET}@example.com/repo.git");

        let mut source = source();
        let git = source.git.as_mut().expect("the fixture is a Git source");
        git.repo_url = remote.clone();

        let mut status = ApplicationStatus::default();
        let recorded = record_sync_success(
            &mut status,
            Some(SHA_V1.to_owned()),
            Some(&source),
            &[],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        recorded.entry().expect("appended");

        let json = serde_json::to_value(&status).expect("status serializes");
        let recorded_url = json["history"][0]["sourceSummary"]["repoURL"]
            .as_str()
            .expect("repoURL is a string");
        assert!(
            !recorded_url.contains(SECRET),
            "the token must never reach /status: {recorded_url}"
        );
        assert_eq!(
            recorded_url, "https://user:***@example.com/repo.git",
            "the shared Git redactor keeps the login and the host so the entry still names the \
             source, and masks only the secret"
        );
        assert!(
            !json.to_string().contains(SECRET),
            "no part of /status may carry the token: {json}"
        );

        // An SCP-style login is not a credential and survives redaction.
        let mut scp = source.clone();
        scp.git.as_mut().expect("git").repo_url =
            "git@github.com:ferris-cd/manifests.git".to_owned();
        let mut status = ApplicationStatus::default();
        let _ = record_sync_success(
            &mut status,
            Some(SHA_V1.to_owned()),
            Some(&scp),
            &[],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        assert_eq!(
            status.history[0]
                .source_summary
                .as_ref()
                .expect("summary")
                .repo_url,
            "git@github.com:ferris-cd/manifests.git"
        );

        // An OCI reference is redacted with the registry rule, which treats every `@` before the
        // path as userinfo (a registry reference has no SCP-style form).
        let mut oci = source.clone();
        oci.git = None;
        oci.oci = Some(ferriscd_crd::OciSourceSpec {
            url: format!("oci://robot:{SECRET}@ghcr.io/payments/charts"),
            tag: Some("1.4.2".to_owned()),
            digest: None,
            path: "charts/api".to_owned(),
        });
        let mut status = ApplicationStatus::default();
        let recorded = record_sync_success(
            &mut status,
            Some("sha256:".to_owned() + &"a".repeat(64)),
            Some(&oci),
            &[],
            10,
            at("2026-11-24T12:00:00Z"),
        );
        let summary = recorded
            .entry()
            .expect("appended")
            .source_summary
            .clone()
            .expect("summary");
        assert_eq!(summary.repo_url, "oci://[REDACTED]@ghcr.io/payments/charts");
        assert_eq!(summary.path, "charts/api");
        assert_eq!(
            summary.target_revision, "1.4.2",
            "the tag is the requested revision the history entry records"
        );
        assert!(!summary.repo_url.contains(SECRET));
    }

    fn succeeded_operation(
        revision: Option<&str>,
        started_at: Time,
        finished_at: Time,
    ) -> OperationState {
        OperationState {
            phase: OperationPhase::Succeeded,
            sync_phase: Some(ferriscd_crd::status::SyncPhase::Succeeded),
            current_wave: 0,
            phase_started_at: Some(started_at.clone()),
            revision: revision.map(str::to_owned),
            active_hooks: Vec::new(),
            metric_gate: None,
            message: Some("sync completed".to_owned()),
            started_at,
            finished_at: Some(finished_at),
        }
    }

    /// Finding M-5: the machine keeps reporting `Finished` for a terminal operation, so recording
    /// must be idempotent — a second pass must not append a duplicate history entry or churn ids.
    #[test]
    fn repeated_finished_passes_do_not_churn_history() {
        let operation = succeeded_operation(
            Some(SHA_V1),
            at("2026-11-24T11:59:00Z"),
            at("2026-11-24T12:00:00Z"),
        );
        let mut status = ApplicationStatus::default();

        let first = record_operation_success(&mut status, &operation, Some(&source()), &[], 10);
        let entry = first
            .entry()
            .expect("the transition into Succeeded appends")
            .clone();
        assert!(first.is_first());
        assert_eq!(entry.id, 1);
        assert_eq!(entry.deployed_at, at("2026-11-24T12:00:00Z"));
        let after_first = status.clone();

        // Every subsequent `Finished` pass is a no-op, byte for byte.
        for _ in 0..3 {
            let again = record_operation_success(&mut status, &operation, Some(&source()), &[], 10);
            assert_eq!(again, SyncRecording::AlreadyRecorded { id: 1 });
            assert!(!again.is_first());
            assert!(again.entry().is_none());
            assert_eq!(
                status, after_first,
                "a repeated pass must not touch /status"
            );
        }

        // A genuinely new operation on a later revision still appends.
        let next = succeeded_operation(
            Some(SHA_V2),
            at("2026-11-24T12:29:00Z"),
            at("2026-11-24T12:30:00Z"),
        );
        let third = record_operation_success(&mut status, &next, Some(&source()), &[], 10);
        assert_eq!(third.entry().expect("appended").id, 2);
        assert_eq!(status.history.len(), 2);

        // A re-sync of the *same* commit is a new operation (new `finishedAt`), so it is recorded.
        let resync = succeeded_operation(
            Some(SHA_V2),
            at("2026-11-24T12:39:00Z"),
            at("2026-11-24T12:40:00Z"),
        );
        let fourth = record_operation_success(&mut status, &resync, Some(&source()), &[], 10);
        assert_eq!(fourth.entry().expect("appended").id, 3);

        // A running (or failed) operation is never recorded.
        let mut running = operation.clone();
        running.phase = OperationPhase::Running;
        running.revision = Some("sha-running".to_owned());
        assert_eq!(
            record_operation_success(&mut status, &running, Some(&source()), &[], 10),
            SyncRecording::NotSucceeded
        );
        assert_eq!(status.history.len(), 3);
    }

    /// Finding M-4: the rollback warning must not outlive the rollback it describes.
    #[test]
    fn the_rollback_warning_is_cleared_when_automation_is_reenabled() {
        let status = status_with(vec![entry(2, Some(SHA_V2)), entry(1, Some(SHA_V1))]);
        let decision = plan_rollback(
            &status,
            RollbackRequest { id: 1 },
            &at("2026-11-24T12:10:00Z"),
        )
        .expect("rollback");

        let mut rolled_back = ApplicationStatus::default();
        rolled_back.set_condition(decision.condition.clone());
        assert!(
            rolled_back.conditions.iter().any(|condition| {
                condition.reason == REASON_AUTOMATED_SYNC_DISABLED_BY_ROLLBACK
            })
        );

        // While automation is still disabled the warning must stay (it is the only hint).
        let mut disabled = app_with_automated(true);
        assert!(decision.apply_to_spec(&mut disabled.spec));
        assert!(
            !clear_rollback_warning_if_automation_reenabled(&disabled.spec, &mut rolled_back),
            "a manual-only application keeps its warning"
        );
        assert_eq!(rolled_back.conditions.len(), 1);

        // Re-enabling automation is the action the warning asked for, so it is cleared exactly once.
        let mut reenabled = disabled.clone();
        reenabled.spec.sync_policy = app_with_automated(true).spec.sync_policy;
        assert!(
            reenabled
                .spec
                .sync_policy
                .as_ref()
                .expect("policy")
                .is_automated()
        );
        assert!(clear_rollback_warning_if_automation_reenabled(
            &reenabled.spec,
            &mut rolled_back
        ));
        assert!(rolled_back.conditions.is_empty());
        assert!(!clear_rollback_warning_if_automation_reenabled(
            &reenabled.spec,
            &mut rolled_back
        ));
        assert!(!clear_rollback_warning(&mut rolled_back));

        // An unrelated condition is never removed.
        let mut other = ApplicationStatus::default();
        other.mark_ready(
            ferriscd_crd::status::REASON_SYNC_SUCCEEDED,
            "synced",
            at("2026-11-24T12:00:00Z"),
        );
        assert!(!clear_rollback_warning(&mut other));
        assert_eq!(other.conditions.len(), 1);
    }
}
