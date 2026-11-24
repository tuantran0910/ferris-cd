//! `Application` status subresource: sync/health observability, compact GKNN inventory,
//! and re-entrant operation state.
//!
//! The status is written through the `/status` subresource on every reconcile (both on
//! success and on error), so it must stay small: an `etcd` object is capped at 1.5 MiB
//! and `Application` must remain a few tens of KiB even with 500 managed resources
//! (trap T9). Consequently this module never stores rendered YAML or diffs, inventory
//! entries are version-agnostic GKNN keys, history is hard-capped, and per-resource
//! summaries are both count- and length-bounded.

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::application::MAX_REVISION_HISTORY_LIMIT;

/// Hard cap on `status.history` entries.
///
/// Must stay equal to [`MAX_REVISION_HISTORY_LIMIT`]; a test enforces the invariant.
pub const MAX_HISTORY_ENTRIES: usize = 20;

/// Hard cap on `status.resources` summaries; overflow is counted in `resourcesOmitted`.
pub const MAX_RESOURCE_STATUSES: usize = 100;

/// Maximum length (in `char`s) of a per-resource status message.
pub const MAX_STATUS_MESSAGE_CHARS: usize = 200;

/// `Ready` condition type, set on every reconcile.
pub const CONDITION_READY: &str = "Ready";

/// Reason recorded when a reconcile finished successfully.
pub const REASON_SYNC_SUCCEEDED: &str = "SyncSucceeded";

/// Reason recorded when a reconcile failed (condition `Ready=False`).
pub const REASON_SYNC_ERROR: &str = "SyncError";

/// Wire-compatible mirror of `metav1.ConditionStatus`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema, Default)]
pub enum ConditionStatus {
    /// The condition is satisfied.
    True,
    /// The condition is not satisfied.
    False,
    /// The condition could not be evaluated.
    #[default]
    Unknown,
}

/// Wire-compatible mirror of `metav1.Condition`.
///
/// Field names and values match the Kubernetes API so `kubectl wait --for=condition=Ready`
/// and `kubectl describe` behave exactly as for built-in resources.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Condition type (e.g. [`CONDITION_READY`]).
    #[serde(rename = "type")]
    pub type_: String,

    /// Whether the condition currently holds.
    pub status: ConditionStatus,

    /// CamelCase machine-readable reason for the current status.
    pub reason: String,

    /// Human-readable message; always present on the wire for `metav1.Condition` parity.
    #[serde(default)]
    pub message: String,

    /// When `status` last changed. Preserved while `status` is unchanged.
    pub last_transition_time: Time,

    /// `metadata.generation` observed when the condition was computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

impl Condition {
    /// Builds a condition.
    #[must_use]
    pub fn new(
        type_: impl Into<String>,
        status: ConditionStatus,
        reason: impl Into<String>,
        message: impl Into<String>,
        last_transition_time: Time,
    ) -> Self {
        Self {
            type_: type_.into(),
            status,
            reason: reason.into(),
            message: message.into(),
            last_transition_time,
            observed_generation: None,
        }
    }

    /// Builds a `Ready` condition with `status` and the given reason/message.
    #[must_use]
    pub fn ready(
        status: ConditionStatus,
        reason: impl Into<String>,
        message: impl Into<String>,
        last_transition_time: Time,
    ) -> Self {
        Self::new(
            CONDITION_READY,
            status,
            reason,
            message,
            last_transition_time,
        )
    }

    /// Records `metadata.generation` on the condition (builder style).
    #[must_use]
    pub fn with_observed_generation(mut self, generation: Option<i64>) -> Self {
        self.observed_generation = generation;
        self
    }

    /// Returns whether this condition is `Ready=True`.
    #[must_use]
    pub fn is_true(&self) -> bool {
        self.status == ConditionStatus::True
    }
}

/// Sync status lattice (`Synced` | `OutOfSync` | `Unknown`).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema, Default)]
pub enum SyncStatus {
    /// Live state matches the desired state.
    Synced,
    /// Live state differs from the desired state.
    OutOfSync,
    /// Sync status could not be determined.
    #[default]
    Unknown,
}

/// Health status values.
///
/// The aggregation precedence (`Degraded > Missing > Progressing > Suspended > Healthy >
/// Unknown`) is implemented by the health evaluator in Phase 09; this type only fixes the
/// wire values so `Application.status.health` stays stable across phases.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema, Default)]
pub enum HealthStatus {
    /// Every managed resource is healthy.
    Healthy,
    /// At least one resource is still converging.
    Progressing,
    /// At least one resource reports a failure.
    Degraded,
    /// At least one resource is intentionally paused/suspended.
    Suspended,
    /// At least one expected resource does not exist.
    Missing,
    /// Health could not be determined.
    #[default]
    Unknown,
}

/// Phase of the current/last operation.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash, JsonSchema)]
pub enum OperationPhase {
    /// The operation is still running (persisted across requeues).
    Running,
    /// The operation completed successfully.
    Succeeded,
    /// The operation completed and at least one resource failed.
    Failed,
    /// The operation aborted with a terminal error.
    Error,
}

/// Sync observability for the last reconcile.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SyncState {
    /// Current sync status.
    pub status: SyncStatus,

    /// Revision (commit SHA) currently deployed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Last revision that was successfully synced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_revision: Option<String>,

    /// Hash of `spec.source` at the last successful sync.
    ///
    /// Guards `selfHeal: false` against spec edits that do not produce a new commit
    /// (finding H7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_spec_hash: Option<String>,

    /// When the last successful sync finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<Time>,
}

impl SyncState {
    /// Builds sync state with the given status and revision.
    #[must_use]
    pub fn new(status: SyncStatus, revision: Option<String>) -> Self {
        Self {
            status,
            revision,
            last_synced_revision: None,
            last_synced_spec_hash: None,
            last_synced_at: None,
        }
    }
}

/// Aggregated health of the managed resources.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthState {
    /// Aggregated health status.
    pub status: HealthStatus,

    /// Short human-readable explanation (never contains secret values).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl HealthState {
    /// Builds health state without a message.
    #[must_use]
    pub fn new(status: HealthStatus) -> Self {
        Self {
            status,
            message: None,
        }
    }
}

/// Version-agnostic inventory entry keyed by GKNN (`<group>/<kind>/<namespace>/<name>`),
/// with the API version stored separately as a non-key hint.
///
/// Keying on Group/Kind/Namespace/Name only is what prevents an API version upgrade
/// (`v1beta1` -> `v1`) from turning the live object into an orphan and self-pruning it
/// (review finding C2 / ADR-003).
#[derive(
    Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct InventoryEntry {
    /// Canonical GKNN string: `<group>/<kind>/<namespace>/<name>` (empty namespace for
    /// cluster-scoped resources, empty group for the core group). Never contains a version.
    pub key: String,

    /// API version hint (`v1`, `apps/v1`, ...). Not part of resource identity.
    #[serde(default)]
    pub version: String,
}

impl InventoryEntry {
    /// Builds an inventory entry from a GKNN key and a version hint.
    #[must_use]
    pub fn new(key: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            version: version.into(),
        }
    }

    /// Returns whether `key` has the canonical four-segment GKNN shape.
    #[must_use]
    pub fn is_gknn_shaped(&self) -> bool {
        let mut segments = self.key.split('/');
        let (Some(_group), Some(kind), Some(_namespace), Some(name), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return false;
        };
        !kind.is_empty() && !name.is_empty()
    }
}

/// Bounded per-resource status summary.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceStatus {
    /// GKNN key of the resource (same shape as [`InventoryEntry::key`]).
    pub key: String,

    /// API version hint of the resource.
    #[serde(default)]
    pub version: String,

    /// Health of this single resource.
    pub health: HealthStatus,

    /// Bounded human-readable message (truncated to [`MAX_STATUS_MESSAGE_CHARS`]).
    #[serde(default)]
    pub message: String,
}

impl ResourceStatus {
    /// Builds a per-resource summary.
    #[must_use]
    pub fn new(
        key: impl Into<String>,
        version: impl Into<String>,
        health: HealthStatus,
        message: impl Into<String>,
    ) -> Self {
        Self {
            key: key.into(),
            version: version.into(),
            health,
            message: message.into(),
        }
    }
}

/// Re-entrant operation state, persisted so requeues never restart a multi-wave sync.
///
/// `v1alpha1` keeps only cross-requeue progress (phase, wave, revision, timestamps).
/// Per-resource wave/hook outcomes are added by the wave state machine in Phase 10
/// (`T10.x`) as additive fields.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OperationState {
    /// Current phase.
    pub phase: OperationPhase,

    /// Sync wave currently being applied (default `0`).
    #[serde(default)]
    pub current_wave: i32,

    /// Revision being operated on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// Bounded human-readable progress/error message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// When the operation started.
    pub started_at: Time,

    /// When the operation finished (`None` while `phase` is `Running`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Time>,
}

/// Metadata-only deployment history entry (never stores manifest content).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RevisionHistoryEntry {
    /// Monotonic deployment id.
    pub id: i64,

    /// Revision (commit SHA) that was deployed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,

    /// When the revision was deployed.
    pub deployed_at: Time,
}

impl RevisionHistoryEntry {
    /// Builds a history entry.
    #[must_use]
    pub fn new(id: i64, revision: Option<String>, deployed_at: Time) -> Self {
        Self {
            id,
            revision,
            deployed_at,
        }
    }
}

/// `Application` `/status` subresource.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationStatus {
    /// `metadata.generation` observed by the last reconcile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,

    /// Standard conditions (`Ready`, ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,

    /// Sync observability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncState>,

    /// Aggregated health.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthState>,

    /// Crash-safe, version-agnostic inventory of every resource owned by this application.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inventory: Vec<InventoryEntry>,

    /// Persisted operation state (multi-wave / hook / rollback progress).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_state: Option<OperationState>,

    /// Bounded deployment history (newest first, at most [`MAX_HISTORY_ENTRIES`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<RevisionHistoryEntry>,

    /// Bounded per-resource health summaries (at most [`MAX_RESOURCE_STATUSES`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceStatus>,

    /// Number of per-resource summaries dropped because of [`MAX_RESOURCE_STATUSES`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub resources_omitted: u32,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

impl ApplicationStatus {
    /// Returns the condition of the given type, if present.
    #[must_use]
    pub fn condition(&self, type_: &str) -> Option<&Condition> {
        self.conditions
            .iter()
            .find(|condition| condition.type_ == type_)
    }

    /// Returns whether the `Ready` condition is `True`.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.condition(CONDITION_READY)
            .is_some_and(Condition::is_true)
    }

    /// Inserts or updates a condition.
    ///
    /// `lastTransitionTime` is preserved whenever the condition `status` is unchanged, so
    /// repeated reconciles that keep reporting the same state never churn the field (and
    /// never trigger watch storms). `reason`/`message`/`observedGeneration` are always
    /// refreshed.
    pub fn set_condition(&mut self, condition: Condition) {
        match self
            .conditions
            .iter_mut()
            .find(|existing| existing.type_ == condition.type_)
        {
            Some(existing) if existing.status == condition.status => {
                existing.reason = condition.reason;
                existing.message = condition.message;
                existing.observed_generation = condition.observed_generation;
            }
            Some(existing) => *existing = condition,
            None => self.conditions.push(condition),
        }
    }

    /// Records `Ready=True` with the given reason/message/transition time.
    pub fn mark_ready(
        &mut self,
        reason: impl Into<String>,
        message: impl Into<String>,
        last_transition_time: Time,
    ) {
        self.set_condition(Condition::ready(
            ConditionStatus::True,
            reason,
            message,
            last_transition_time,
        ));
    }

    /// Records `Ready=False` (terminal or retryable failure) with the given reason.
    pub fn mark_not_ready(
        &mut self,
        reason: impl Into<String>,
        message: impl Into<String>,
        last_transition_time: Time,
    ) {
        self.set_condition(Condition::ready(
            ConditionStatus::False,
            reason,
            message,
            last_transition_time,
        ));
    }

    /// Records `Ready=False` with reason [`REASON_SYNC_ERROR`].
    pub fn mark_sync_error(&mut self, message: impl Into<String>, last_transition_time: Time) {
        self.mark_not_ready(REASON_SYNC_ERROR, message, last_transition_time);
    }

    /// Replaces the inventory with `entries`, sorted by key and de-duplicated by GKNN.
    ///
    /// Sorting keeps `/status` patches byte-stable so an unchanged inventory never
    /// produces a spurious diff. A later duplicate key wins, and its `version` hint is
    /// refreshed without ever changing the key.
    pub fn set_inventory(&mut self, entries: impl IntoIterator<Item = InventoryEntry>) {
        let mut sorted: Vec<InventoryEntry> = entries.into_iter().collect();
        sorted.sort_by(|left, right| left.key.cmp(&right.key));
        sorted.dedup_by(|later, earlier| {
            if later.key == earlier.key {
                earlier.version = std::mem::take(&mut later.version);
                true
            } else {
                false
            }
        });
        self.inventory = sorted;
    }

    /// Pushes a history entry (newest first) and truncates to the application's
    /// `revisionHistoryLimit`, clamped to `1..=MAX_HISTORY_ENTRIES`.
    pub fn push_history(&mut self, entry: RevisionHistoryEntry, revision_history_limit: i32) {
        self.history.insert(0, entry);
        let cap = revision_history_limit.clamp(1, MAX_REVISION_HISTORY_LIMIT) as usize;
        self.history.truncate(cap.min(MAX_HISTORY_ENTRIES));
    }

    /// Inserts or replaces a per-resource summary, enforcing the count bound and
    /// truncating the message to [`MAX_STATUS_MESSAGE_CHARS`].
    pub fn record_resource_status(&mut self, mut status: ResourceStatus) {
        truncate_chars(&mut status.message, MAX_STATUS_MESSAGE_CHARS);

        if let Some(existing) = self
            .resources
            .iter_mut()
            .find(|existing| existing.key == status.key)
        {
            *existing = status;
            return;
        }

        if self.resources.len() >= MAX_RESOURCE_STATUSES {
            self.resources_omitted = self.resources_omitted.saturating_add(1);
            return;
        }

        self.resources.push(status);
    }
}

/// Truncates `value` in place to at most `max_chars` characters, respecting UTF-8
/// boundaries (never panics on multi-byte input).
fn truncate_chars(value: &mut String, max_chars: usize) {
    if value.chars().count() <= max_chars {
        return;
    }
    let truncated: String = value.chars().take(max_chars).collect();
    *value = truncated;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn ts(rfc3339: &str) -> Time {
        Time(
            rfc3339
                .parse()
                .expect("test timestamps must be valid RFC 3339"),
        )
    }

    fn gknn(index: usize) -> String {
        format!("apps/Deployment/payments/payment-api-{index}")
    }

    /// 500 inventory entries + 20 history entries must stay far below the 1.5 MiB `etcd`
    /// limit and below the 100 KB status budget (trap T9).
    #[test]
    fn large_status_stays_under_etcd_budget() {
        let mut status = ApplicationStatus {
            observed_generation: Some(42),
            ..ApplicationStatus::default()
        };

        let entries = (0..500).map(|index| InventoryEntry::new(gknn(index), "apps/v1"));
        status.set_inventory(entries);

        for index in 0..25 {
            status.push_history(
                RevisionHistoryEntry::new(
                    index,
                    Some("8f3a1c2e9d4b5a60718293a4b5c6d7e8f9012345".to_owned()),
                    ts("2026-11-24T12:00:00Z"),
                ),
                MAX_REVISION_HISTORY_LIMIT,
            );
        }

        for index in 0..(MAX_RESOURCE_STATUSES + 10) {
            status.record_resource_status(ResourceStatus::new(
                gknn(index),
                "apps/v1",
                HealthStatus::Healthy,
                "deployment is available",
            ));
        }

        status.mark_ready(
            REASON_SYNC_SUCCEEDED,
            "Reconciled revision 8f3a1c2",
            ts("2026-11-24T12:00:00Z"),
        );
        status.sync = Some(SyncState {
            status: SyncStatus::Synced,
            revision: Some("8f3a1c2e9d4b5a60718293a4b5c6d7e8f9012345".to_owned()),
            last_synced_revision: Some("8f3a1c2e9d4b5a60718293a4b5c6d7e8f9012345".to_owned()),
            last_synced_spec_hash: Some("a1b2c3d4e5f6".to_owned()),
            last_synced_at: Some(ts("2026-11-24T12:00:00Z")),
        });
        status.health = Some(HealthState {
            status: HealthStatus::Healthy,
            message: Some("All 4 resources are healthy".to_owned()),
        });

        assert_eq!(status.inventory.len(), 500);
        assert_eq!(status.history.len(), MAX_HISTORY_ENTRIES);
        assert_eq!(status.resources.len(), MAX_RESOURCE_STATUSES);
        assert_eq!(status.resources_omitted, 10);

        let json = serde_json::to_string(&status).expect("status must serialize");
        assert!(
            json.len() < 100_000,
            "status JSON is {} bytes, expected < 100000",
            json.len()
        );
    }

    #[test]
    fn condition_transitions_preserve_last_transition_time() {
        let first_seen = ts("2026-11-24T12:00:00Z");
        let later = ts("2026-11-24T12:10:00Z");
        let much_later = ts("2026-11-24T13:00:00Z");

        let mut status = ApplicationStatus::default();
        assert!(!status.is_ready());
        assert!(status.condition(CONDITION_READY).is_none());

        status.mark_ready(REASON_SYNC_SUCCEEDED, "first sync", first_seen.clone());
        assert!(status.is_ready());
        let condition = status
            .condition(CONDITION_READY)
            .expect("Ready condition must exist");
        assert_eq!(condition.status, ConditionStatus::True);
        assert_eq!(condition.last_transition_time, first_seen);
        assert_eq!(condition.reason, REASON_SYNC_SUCCEEDED);

        // Same status, refreshed message: transition time must not move.
        status.mark_ready(REASON_SYNC_SUCCEEDED, "re-synced", later.clone());
        let condition = status
            .condition(CONDITION_READY)
            .expect("Ready condition must exist");
        assert_eq!(condition.message, "re-synced");
        assert_eq!(
            condition.last_transition_time, first_seen,
            "unchanged status must preserve lastTransitionTime"
        );

        // Status change: transition time must move to the new observation.
        status.mark_sync_error("repo unreachable", later.clone());
        let condition = status
            .condition(CONDITION_READY)
            .expect("Ready condition must exist");
        assert_eq!(condition.status, ConditionStatus::False);
        assert_eq!(condition.reason, REASON_SYNC_ERROR);
        assert_eq!(condition.last_transition_time, later);
        assert!(!status.is_ready());

        // Repeated failure keeps the failure transition time.
        status.mark_sync_error("repo still unreachable", much_later);
        let condition = status
            .condition(CONDITION_READY)
            .expect("Ready condition must exist");
        assert_eq!(condition.message, "repo still unreachable");
        assert_eq!(condition.last_transition_time, later);
        assert_eq!(status.conditions.len(), 1);
    }

    #[test]
    fn conditions_serialize_with_metav1_field_names() {
        let mut status = ApplicationStatus::default();
        status.mark_ready(
            REASON_SYNC_SUCCEEDED,
            "Reconciled revision 8f3a1c2",
            ts("2026-11-24T12:00:00Z"),
        );

        let json = serde_json::to_value(&status).expect("status must serialize");
        let condition = &json["conditions"][0];
        assert_eq!(condition["type"], "Ready");
        assert_eq!(condition["status"], "True");
        assert_eq!(condition["reason"], "SyncSucceeded");
        assert_eq!(condition["lastTransitionTime"], "2026-11-24T12:00:00Z");
        assert!(condition.get("last_transition_time").is_none());
    }

    #[test]
    fn inventory_keys_are_version_agnostic_gknn() {
        let entry = InventoryEntry::new("/Service/payments/payment-api", "v1");
        assert!(entry.is_gknn_shaped());

        // Simulated API upgrade: only the version hint changes, never the key.
        let upgraded = InventoryEntry::new(entry.key.clone(), "v1beta1");
        assert_eq!(upgraded.key, entry.key);
        assert_ne!(upgraded.version, entry.version);
        assert_eq!(
            entry.key.split('/').count(),
            4,
            "GKNN must be group/kind/namespace/name with no version segment"
        );

        let mut status = ApplicationStatus::default();
        status.set_inventory(vec![
            InventoryEntry::new(gknn(2), "apps/v1"),
            InventoryEntry::new(gknn(0), "apps/v1beta1"),
            InventoryEntry::new(gknn(1), "apps/v1"),
            InventoryEntry::new(gknn(1), "apps/v1"),
        ]);
        let keys: Vec<&str> = status
            .inventory
            .iter()
            .map(|entry| entry.key.as_str())
            .collect();
        let unique: BTreeSet<&str> = keys.iter().copied().collect();
        assert_eq!(keys, vec![gknn(0), gknn(1), gknn(2)]);
        assert_eq!(
            unique.len(),
            status.inventory.len(),
            "duplicates must collapse"
        );

        // Version upgrade through set_inventory keeps the key set identical.
        let before: Vec<String> = status.inventory.iter().map(|e| e.key.clone()).collect();
        status.set_inventory(
            before
                .iter()
                .map(|key| InventoryEntry::new(key.clone(), "v1")),
        );
        let after: Vec<String> = status.inventory.iter().map(|e| e.key.clone()).collect();
        assert_eq!(before, after);

        let serialized = serde_json::to_value(&status.inventory[0]).expect("entry must serialize");
        assert_eq!(serialized["key"], gknn(0));
        assert_eq!(serialized["version"], "v1");
    }

    #[test]
    fn gknn_shape_rejects_versioned_or_truncated_keys() {
        for bad in [
            "apps/v1/Deployment/payments/api",
            "Deployment/payments/api",
            "apps//payments/api",
            "apps/Deployment//",
            "",
        ] {
            assert!(
                !InventoryEntry::new(bad, "v1").is_gknn_shaped(),
                "expected {bad:?} to be rejected"
            );
        }
        for good in [
            "apps/Deployment/payments/api",
            "/Service/payments/api",
            "rbac.authorization.k8s.io/ClusterRole//admin",
        ] {
            assert!(
                InventoryEntry::new(good, "v1").is_gknn_shaped(),
                "expected {good:?} to be accepted"
            );
        }
    }

    #[test]
    fn history_is_capped_by_limit_and_request_floor() {
        assert_eq!(MAX_HISTORY_ENTRIES, MAX_REVISION_HISTORY_LIMIT as usize);

        let mut status = ApplicationStatus::default();
        for id in 0..5 {
            status.push_history(
                RevisionHistoryEntry::new(
                    id,
                    Some(format!("rev-{id}")),
                    ts("2026-11-24T12:00:00Z"),
                ),
                3,
            );
        }
        assert_eq!(status.history.len(), 3);
        let ids: Vec<i64> = status.history.iter().map(|entry| entry.id).collect();
        assert_eq!(ids, vec![4, 3, 2], "newest entries must be kept first");

        // A nonsensical limit still leaves at least one entry.
        status.push_history(
            RevisionHistoryEntry::new(99, None, ts("2026-11-24T12:00:00Z")),
            0,
        );
        assert_eq!(status.history.len(), 1);
    }

    #[test]
    fn resource_status_messages_are_truncated_and_bounded() {
        let mut status = ApplicationStatus::default();
        let long_message = "é".repeat(MAX_STATUS_MESSAGE_CHARS * 2);
        status.record_resource_status(ResourceStatus::new(
            gknn(0),
            "apps/v1",
            HealthStatus::Degraded,
            long_message,
        ));
        let message = &status.resources[0].message;
        assert_eq!(message.chars().count(), MAX_STATUS_MESSAGE_CHARS);
        assert!(message.chars().all(|c| c == 'é'), "UTF-8 must not be split");

        // Re-recording the same key replaces rather than appends.
        status.record_resource_status(ResourceStatus::new(
            gknn(0),
            "apps/v1",
            HealthStatus::Healthy,
            "ok",
        ));
        assert_eq!(status.resources.len(), 1);
        assert_eq!(status.resources[0].health, HealthStatus::Healthy);

        // Overflow beyond the bound is counted, never appended.
        let mut overflow = ApplicationStatus::default();
        for index in 0..(MAX_RESOURCE_STATUSES + 3) {
            overflow.record_resource_status(ResourceStatus::new(
                gknn(index),
                "apps/v1",
                HealthStatus::Healthy,
                "ok",
            ));
        }
        assert_eq!(overflow.resources.len(), MAX_RESOURCE_STATUSES);
        assert_eq!(overflow.resources_omitted, 3);
    }

    #[test]
    fn empty_status_serializes_without_noise() {
        let status = ApplicationStatus::default();
        let json = serde_json::to_value(&status).expect("status must serialize");
        assert_eq!(json, serde_json::json!({}));
        assert_eq!(status.conditions.len(), 0);
        assert!(!status.is_ready());
    }
}
