//! The engine-side diff model: statuses, field changes, conflicts, and the summary the sync
//! decision gate consumes.
//!
//! These types are deliberately independent of any Kubernetes client (no `kube`, no `gix`):
//! the controller performs the SSA dry-run calls ([`crate::diff`] never does I/O) and hands the
//! resulting payloads to [`ResourceDiff::compare`](crate::diff::ResourceDiff::compare), which
//! is the **only** constructor that accepts raw objects and therefore the only place where
//! `Secret` redaction must (and does) happen.
//!
//! The status lattice is:
//!
//! | [`DiffStatus`] | Meaning | Sync consequence |
//! |---|---|---|
//! | `Synced` | canonicalized live == predicted | nothing to do |
//! | `OutOfSync` | at least one field differs, or the dry-run reported field conflicts | apply |
//! | `Missing` | not created yet, or deferred on a CRD/namespace (dry-run skipped) | create |
//! | `Orphaned` | tracked in `status.inventory` but no longer in Git | prune (when allowed) |
//! | `OwnershipConflict` | live object belongs to another `Application` | fail, never touch |
//!
//! `OutOfSync` and `Missing` resources count as drift: `selfHeal: true` applies them.
//! `OwnershipConflict` is deliberately **not** drift — it is a *terminal* classification. The
//! object belongs to another `Application`, so no apply FerrisCD could make would resolve it;
//! counting it as drift made `selfHeal: true` execute (and fail, or worse, force) on every single
//! reconcile. It is still reported: [`DiffSummary::has_ownership_conflicts`] keeps
//! `Application.status.sync.status` at `OutOfSync` until an operator resolves the conflict.

use std::fmt;

use ferriscd_crd::status::SyncStatus;
use serde::Serialize;
use serde::ser::SerializeStruct;
use serde_json::Value;

use crate::manifest::ResourceKey;

/// Kind of change reported for one JSON path.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum ChangeKind {
    /// The path exists only in the predicted object (the API server added or defaulted it).
    Added,
    /// The path exists only in the live object (it was removed from Git or by another actor).
    Removed,
    /// The path exists on both sides with different values.
    Modified,
}

impl ChangeKind {
    /// The wire form of this change kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Modified => "modified",
        }
    }
}

impl fmt::Display for ChangeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One structured field-level difference.
///
/// `path` is an RFC 6901 JSON Pointer into the *canonicalized, redacted* object, so it can be
/// shown to a user directly. `live`/`predicted` are the values at that path after `Secret`
/// redaction and `ignoreDifferences` — never raw secret material.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FieldChange {
    /// RFC 6901 JSON Pointer (`/spec/replicas`, `/data/password`).
    pub path: String,
    /// Whether the path was added, removed, or modified.
    pub kind: ChangeKind,
    /// Live value at `path` (`None` for [`ChangeKind::Added`]), already redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live: Option<Value>,
    /// Predicted value at `path` (`None` for [`ChangeKind::Removed`]), already redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicted: Option<Value>,
}

impl FieldChange {
    /// Builds a field change.
    ///
    /// # Secret hygiene
    ///
    /// The values are stored verbatim, so callers **must** pass already-redacted values;
    /// nothing outside [`ResourceDiff::compare`](crate::diff::ResourceDiff::compare) should
    /// construct a [`FieldChange`] from live/predicted payloads.
    #[must_use]
    pub fn new(
        path: impl Into<String>,
        kind: ChangeKind,
        live: Option<Value>,
        predicted: Option<Value>,
    ) -> Self {
        Self {
            path: path.into(),
            kind,
            live,
            predicted,
        }
    }
}

/// One Server-Side Apply field-ownership conflict (finding H6).
///
/// Kubernetes answers a conflicting `Patch::Apply` with `409 Conflict` and a `Status` whose
/// `details.causes` name the field manager that owns the disputed field. Reporting that
/// structure lets an operator fix the `Application` (or list the manager in
/// `syncOptions.takeoverFieldManagers`) instead of staring at an opaque error.
#[derive(
    serde::Serialize,
    serde::Deserialize,
    Debug,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "camelCase")]
pub struct FieldConflict {
    /// The conflicting field as reported by the API server (a dot-separated Kubernetes field
    /// path such as `spec.replicas`, without a leading dot). `None` when the server did not
    /// report one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The field manager that owns (or last wrote) the conflicting field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,
}

impl FieldConflict {
    /// Builds a conflict description.
    #[must_use]
    pub fn new(field: Option<String>, manager: Option<String>) -> Self {
        Self { field, manager }
    }

    /// A conflict the API server did not describe in a parseable way.
    ///
    /// Still structured (an empty description rather than an opaque error string), so callers
    /// can report "a field-ownership conflict occurred" without inventing a manager name.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            field: None,
            manager: None,
        }
    }

    /// Returns whether nothing is known about this conflict.
    #[must_use]
    pub fn is_unknown(&self) -> bool {
        self.field.is_none() && self.manager.is_none()
    }
}

impl fmt::Display for FieldConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.field, &self.manager) {
            (Some(field), Some(manager)) => {
                write!(f, "field '{field}' is owned by manager '{manager}'")
            }
            (Some(field), None) => write!(f, "field '{field}' is owned by another manager"),
            (None, Some(manager)) => {
                write!(f, "a conflicting field is owned by manager '{manager}'")
            }
            (None, None) => f.write_str("a field-ownership conflict was reported"),
        }
    }
}

/// Classification of one desired (or previously managed) resource.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum DiffStatus {
    /// Canonicalized live state matches the predicted (dry-run) state.
    Synced,
    /// At least one field differs, or the dry-run reported field-ownership conflicts.
    OutOfSync,
    /// The object does not exist yet, or its dry-run was deliberately skipped because its
    /// `CustomResourceDefinition`/`Namespace` does not exist yet (finding C3).
    Missing,
    /// Tracked in `status.inventory` but no longer present in Git.
    Orphaned,
    /// The live object belongs to a different `Application` (`ferriscd.io/tracking-id`);
    /// it must never be modified or pruned (trap T10).
    OwnershipConflict {
        /// The foreign `tracking-id` exactly as recorded on the live object.
        owner: String,
    },
}

impl DiffStatus {
    /// Returns whether the resource is in sync.
    #[must_use]
    pub fn is_synced(&self) -> bool {
        matches!(self, Self::Synced)
    }

    /// Returns whether the resource differs from Git.
    #[must_use]
    pub fn is_out_of_sync(&self) -> bool {
        matches!(self, Self::OutOfSync)
    }

    /// Returns whether the resource must be created.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    /// Returns whether the resource is an orphan (tracked, no longer in Git).
    #[must_use]
    pub fn is_orphaned(&self) -> bool {
        matches!(self, Self::Orphaned)
    }

    /// Returns whether the live object belongs to another `Application`.
    #[must_use]
    pub fn is_ownership_conflict(&self) -> bool {
        matches!(self, Self::OwnershipConflict { .. })
    }

    /// Returns the foreign owner of an [`DiffStatus::OwnershipConflict`].
    #[must_use]
    pub fn foreign_owner(&self) -> Option<&str> {
        match self {
            Self::OwnershipConflict { owner } => Some(owner),
            _ => None,
        }
    }

    /// Returns whether this status requires an apply (create or update).
    #[must_use]
    pub fn needs_apply(&self) -> bool {
        matches!(self, Self::OutOfSync | Self::Missing)
    }

    /// Returns whether this status counts as drift.
    ///
    /// Drift is what `selfHeal: true` reacts to: an out-of-sync or a missing object. An
    /// [`DiffStatus::OwnershipConflict`] is deliberately excluded — applying cannot resolve an
    /// object owned by another `Application`, so treating it as drift made `selfHeal: true`
    /// execute forever. It stays a distinct, reported status
    /// ([`DiffSummary::has_ownership_conflicts`]).
    #[must_use]
    pub fn is_drift(&self) -> bool {
        matches!(self, Self::OutOfSync | Self::Missing)
    }

    /// The wire form of this status.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Synced => "synced",
            Self::OutOfSync => "outOfSync",
            Self::Missing => "missing",
            Self::Orphaned => "orphaned",
            Self::OwnershipConflict { .. } => "ownershipConflict",
        }
    }
}

impl fmt::Display for DiffStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The complete diff of one resource.
///
/// Fields are private and the only constructor that accepts raw payloads is
/// [`ResourceDiff::compare`](crate::diff::ResourceDiff::compare), which redacts `Secret`
/// values and strips volatile metadata before any change is recorded. That is the enforcement
/// point for trap T4: no `ResourceDiff` — and therefore no diff preview, log line, or API
/// response — can carry a raw secret value.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceDiff {
    pub(crate) key: ResourceKey,
    pub(crate) status: DiffStatus,
    pub(crate) changes: Vec<FieldChange>,
    pub(crate) conflicts: Vec<FieldConflict>,
    pub(crate) truncated: bool,
}

impl ResourceDiff {
    /// Assembles a diff from already-computed parts (crate-internal).
    pub(crate) fn assemble(
        key: ResourceKey,
        status: DiffStatus,
        changes: Vec<FieldChange>,
        conflicts: Vec<FieldConflict>,
        truncated: bool,
    ) -> Self {
        Self {
            key,
            status,
            changes,
            conflicts,
            truncated,
        }
    }

    /// A resource that does not exist yet (or whose dry-run was deferred).
    #[must_use]
    pub fn missing(key: ResourceKey) -> Self {
        Self::assemble(key, DiffStatus::Missing, Vec::new(), Vec::new(), false)
    }

    /// A previously managed resource that is no longer in Git.
    #[must_use]
    pub fn orphaned(key: ResourceKey) -> Self {
        Self::assemble(key, DiffStatus::Orphaned, Vec::new(), Vec::new(), false)
    }

    /// A resource whose live object belongs to another `Application` (trap T10).
    #[must_use]
    pub fn ownership_conflict(key: ResourceKey, owner: impl Into<String>) -> Self {
        Self::assemble(
            key,
            DiffStatus::OwnershipConflict {
                owner: owner.into(),
            },
            Vec::new(),
            Vec::new(),
            false,
        )
    }

    /// A resource whose SSA dry-run failed with `409 Conflict` (finding H6).
    ///
    /// Such a resource is [`DiffStatus::OutOfSync`]: the payload differs, and the difference is
    /// exactly what the API server refused to apply. The conflicts carry the manager names so
    /// the failure is actionable.
    #[must_use]
    pub fn conflicted(key: ResourceKey, conflicts: Vec<FieldConflict>) -> Self {
        Self::assemble(key, DiffStatus::OutOfSync, Vec::new(), conflicts, false)
    }

    /// The version-agnostic identity of the resource.
    #[must_use]
    pub fn key(&self) -> &ResourceKey {
        &self.key
    }

    /// The classification of this resource.
    #[must_use]
    pub fn status(&self) -> &DiffStatus {
        &self.status
    }

    /// Structured field-level changes (bounded by
    /// [`MAX_FIELD_CHANGES`](crate::diff::MAX_FIELD_CHANGES), already redacted).
    #[must_use]
    pub fn changes(&self) -> &[FieldChange] {
        &self.changes
    }

    /// Field-ownership conflicts reported by a `409 Conflict` dry-run.
    #[must_use]
    pub fn conflicts(&self) -> &[FieldConflict] {
        &self.conflicts
    }

    /// Returns whether [`Self::changes`] was truncated to the documented bound.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns whether the resource is in sync (true only for [`DiffStatus::Synced`]).
    #[must_use]
    pub fn is_synced(&self) -> bool {
        self.status.is_synced()
    }
}

impl fmt::Display for ResourceDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} ({} change(s), {} conflict(s)",
            self.key.canonical(),
            self.status,
            self.changes.len(),
            self.conflicts.len()
        )?;
        if self.truncated {
            f.write_str(", truncated")?;
        }
        f.write_str(")")
    }
}

impl Serialize for ResourceDiff {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("ResourceDiff", 5)?;
        state.serialize_field("key", &self.key.canonical())?;
        state.serialize_field("status", &self.status)?;
        state.serialize_field("changes", &self.changes)?;
        state.serialize_field("conflicts", &self.conflicts)?;
        state.serialize_field("truncated", &self.truncated)?;
        state.end()
    }
}

/// Aggregate counts over a whole diff pass, consumed by the sync decision gate.
///
/// Counts only: `Application.status` must stay small (trap T9), so the summary that gets
/// persisted/reported is a handful of integers, never per-resource payloads.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffSummary {
    /// Resources classified in this pass.
    pub total: usize,
    /// Resources whose live state matches the predicted state.
    pub synced: usize,
    /// Resources that differ (including those with field conflicts).
    pub out_of_sync: usize,
    /// Resources that do not exist yet (or whose dry-run was deferred).
    pub missing: usize,
    /// Tracked resources no longer present in Git.
    pub orphaned: usize,
    /// Resources owned by another `Application`.
    pub ownership_conflicts: usize,
    /// Field-ownership conflicts reported by `409 Conflict` dry-runs.
    pub field_conflicts: usize,
}

impl DiffSummary {
    /// Summarizes a diff pass.
    #[must_use]
    pub fn from_diffs<'a>(diffs: impl IntoIterator<Item = &'a ResourceDiff>) -> Self {
        let mut summary = Self::default();
        for diff in diffs {
            summary.total += 1;
            match diff.status() {
                DiffStatus::Synced => summary.synced += 1,
                DiffStatus::OutOfSync => summary.out_of_sync += 1,
                DiffStatus::Missing => summary.missing += 1,
                DiffStatus::Orphaned => summary.orphaned += 1,
                DiffStatus::OwnershipConflict { .. } => summary.ownership_conflicts += 1,
            }
            summary.field_conflicts += diff.conflicts().len();
        }
        summary
    }

    /// Returns whether anything needs applying: an out-of-sync or a missing resource.
    ///
    /// This is the "drift" predicate of the sync decision gate (`selfHeal: true` reacts to it).
    /// [`Self::ownership_conflicts`] is excluded on purpose: a foreign object can never be fixed
    /// by an apply, so counting it here made `selfHeal: true` execute on every reconcile. It is
    /// still reported through [`Self::has_ownership_conflicts`].
    #[must_use]
    pub fn has_drift(&self) -> bool {
        self.out_of_sync > 0 || self.missing > 0
    }

    /// Returns whether any resource is owned by another `Application`.
    ///
    /// Terminal for the sync gate, but never silent: an unresolved ownership conflict keeps
    /// `Application.status.sync.status` at `OutOfSync` (see [`Self::is_synced`]).
    #[must_use]
    pub fn has_ownership_conflicts(&self) -> bool {
        self.ownership_conflicts > 0
    }

    /// Returns whether any tracked resource is an orphan.
    #[must_use]
    pub fn has_orphans(&self) -> bool {
        self.orphaned > 0
    }

    /// Returns whether the whole pass is in sync.
    ///
    /// Orphans and ownership conflicts are not drift (nothing to self-heal), but they are not
    /// "synced" either: both must keep the reported status `OutOfSync`.
    #[must_use]
    pub fn is_synced(&self) -> bool {
        !self.has_drift() && !self.has_orphans() && !self.has_ownership_conflicts()
    }

    /// Maps the summary onto `Application.status.sync.status`.
    ///
    /// Orphans count as `OutOfSync` even when `prune` is disabled: the operator removed a
    /// resource from Git and must be told, even if FerrisCD will not delete it automatically.
    #[must_use]
    pub fn sync_status(&self) -> SyncStatus {
        if self.is_synced() {
            SyncStatus::Synced
        } else {
            SyncStatus::OutOfSync
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn key(kind: &str, name: &str) -> ResourceKey {
        ResourceKey::new("apps", kind, Some("payments".to_owned()), name)
    }

    #[test]
    fn the_summary_counts_every_status() {
        let diffs = vec![
            ResourceDiff::assemble(
                key("Deployment", "api"),
                DiffStatus::Synced,
                Vec::new(),
                Vec::new(),
                false,
            ),
            ResourceDiff::conflicted(
                key("Deployment", "web"),
                vec![FieldConflict::new(
                    Some("spec.replicas".to_owned()),
                    Some("hpa".to_owned()),
                )],
            ),
            ResourceDiff::missing(key("Service", "api")),
            ResourceDiff::orphaned(key("ConfigMap", "old")),
            ResourceDiff::ownership_conflict(key("Secret", "creds"), "ferriscd-system/other"),
        ];

        let summary = DiffSummary::from_diffs(&diffs);
        assert_eq!(summary.total, 5);
        assert_eq!(summary.synced, 1);
        assert_eq!(summary.out_of_sync, 1);
        assert_eq!(summary.missing, 1);
        assert_eq!(summary.orphaned, 1);
        assert_eq!(summary.ownership_conflicts, 1);
        assert_eq!(summary.field_conflicts, 1);
        assert!(summary.has_drift());
        assert!(summary.has_orphans());
        assert!(!summary.is_synced());
        assert_eq!(summary.sync_status(), SyncStatus::OutOfSync);
    }

    #[test]
    fn an_all_synced_summary_is_synced() {
        let diffs = vec![
            ResourceDiff::assemble(
                key("Deployment", "api"),
                DiffStatus::Synced,
                Vec::new(),
                Vec::new(),
                false,
            ),
            ResourceDiff::assemble(
                key("Service", "api"),
                DiffStatus::Synced,
                Vec::new(),
                Vec::new(),
                false,
            ),
        ];
        let summary = DiffSummary::from_diffs(&diffs);
        assert!(summary.is_synced());
        assert!(!summary.has_drift());
        assert!(!summary.has_orphans());
        assert_eq!(summary.sync_status(), SyncStatus::Synced);

        // An empty pass is trivially in sync (nothing to do, nothing drifted).
        let empty = DiffSummary::from_diffs(std::iter::empty::<&ResourceDiff>());
        assert_eq!(empty, DiffSummary::default());
        assert!(empty.is_synced());
        assert_eq!(empty.sync_status(), SyncStatus::Synced);
    }

    #[test]
    fn orphans_alone_still_report_out_of_sync() {
        let diffs = vec![ResourceDiff::orphaned(key("ConfigMap", "old"))];
        let summary = DiffSummary::from_diffs(&diffs);
        assert!(!summary.has_drift(), "an orphan is not live drift");
        assert!(summary.has_orphans());
        assert_eq!(
            summary.sync_status(),
            SyncStatus::OutOfSync,
            "the operator must see that Git dropped a resource"
        );
    }

    /// Finding M4: an ownership conflict is a *terminal* classification, not drift.
    ///
    /// Counting it as drift made `selfHeal: true` execute on every reconcile — an apply that can
    /// never succeed because another `Application` owns the object. It still has to be reported.
    #[test]
    fn ownership_conflicts_are_terminal_but_never_synced() {
        let diffs = vec![ResourceDiff::ownership_conflict(
            key("Secret", "creds"),
            "ferriscd-system/other",
        )];
        let summary = DiffSummary::from_diffs(&diffs);
        assert_eq!(summary.ownership_conflicts, 1);
        assert!(
            !summary.has_drift(),
            "selfHeal: true must not chase an unfixable conflict"
        );
        assert!(summary.has_ownership_conflicts());
        assert!(
            !summary.is_synced(),
            "the operator must still see the conflict"
        );
        assert_eq!(summary.sync_status(), SyncStatus::OutOfSync);
    }

    #[test]
    fn status_helpers_agree_with_their_variants() {
        let missing = ResourceDiff::missing(key("Service", "api"));
        assert!(missing.status().is_missing());
        assert!(missing.status().needs_apply());
        assert!(missing.status().is_drift());
        assert!(!missing.is_synced());

        let orphan = ResourceDiff::orphaned(key("Service", "api"));
        assert!(orphan.status().is_orphaned());
        assert!(!orphan.status().needs_apply());
        assert!(!orphan.status().is_drift());

        let conflict = ResourceDiff::ownership_conflict(key("Service", "api"), "other/app");
        assert!(conflict.status().is_ownership_conflict());
        assert_eq!(conflict.status().foreign_owner(), Some("other/app"));
        assert!(
            !conflict.status().is_drift(),
            "an ownership conflict is terminal, never self-healed"
        );

        let out_of_sync =
            ResourceDiff::conflicted(key("Service", "api"), vec![FieldConflict::unknown()]);
        assert!(out_of_sync.status().is_out_of_sync());
        assert!(out_of_sync.status().needs_apply());
        assert!(out_of_sync.conflicts()[0].is_unknown());
    }

    #[test]
    fn conflicts_render_actionably_without_secrets() {
        let named = FieldConflict::new(
            Some("spec.replicas".to_owned()),
            Some("kubectl-client-side-apply".to_owned()),
        );
        assert_eq!(
            named.to_string(),
            "field 'spec.replicas' is owned by manager 'kubectl-client-side-apply'"
        );
        assert_eq!(
            FieldConflict::new(Some("spec.replicas".to_owned()), None).to_string(),
            "field 'spec.replicas' is owned by another manager"
        );
        assert_eq!(
            FieldConflict::new(None, Some("hpa".to_owned())).to_string(),
            "a conflicting field is owned by manager 'hpa'"
        );
        assert_eq!(
            FieldConflict::unknown().to_string(),
            "a field-ownership conflict was reported"
        );
    }

    #[test]
    fn diffs_serialize_with_a_canonical_gknn_key() {
        let diff = ResourceDiff::assemble(
            key("Deployment", "api"),
            DiffStatus::OutOfSync,
            vec![FieldChange::new(
                "/spec/replicas",
                ChangeKind::Modified,
                Some(json!(1)),
                Some(json!(3)),
            )],
            Vec::new(),
            true,
        );

        let value = serde_json::to_value(&diff).expect("the diff must serialize");
        assert_eq!(value["key"], json!("apps/Deployment/payments/api"));
        assert_eq!(value["status"], json!("outOfSync"));
        assert_eq!(value["changes"][0]["path"], json!("/spec/replicas"));
        assert_eq!(value["changes"][0]["kind"], json!("modified"));
        assert_eq!(value["changes"][0]["live"], json!(1));
        assert_eq!(value["changes"][0]["predicted"], json!(3));
        assert_eq!(value["conflicts"], json!([]));
        assert_eq!(value["truncated"], json!(true));

        // The Display form is one line and never contains a payload.
        let rendered = diff.to_string();
        assert!(
            rendered.starts_with("apps/Deployment/payments/api: outOfSync"),
            "{rendered}"
        );
        assert!(rendered.contains("1 change(s)"), "{rendered}");
        assert!(rendered.contains("truncated"), "{rendered}");
    }

    #[test]
    fn change_kinds_and_statuses_have_stable_wire_names() {
        for (kind, expected) in [
            (ChangeKind::Added, "added"),
            (ChangeKind::Removed, "removed"),
            (ChangeKind::Modified, "modified"),
        ] {
            assert_eq!(kind.as_str(), expected);
            assert_eq!(kind.to_string(), expected);
            assert_eq!(
                serde_json::to_value(kind).expect("serialize"),
                json!(expected)
            );
        }
        assert_eq!(ChangeKind::Added.to_string(), "added");
        assert_eq!(
            DiffStatus::OwnershipConflict {
                owner: "x".to_owned()
            }
            .as_str(),
            "ownershipConflict"
        );
        assert_eq!(
            serde_json::to_value(DiffStatus::OwnershipConflict {
                owner: "ferriscd-system/other".to_owned()
            })
            .expect("serialize"),
            json!({ "ownershipConflict": { "owner": "ferriscd-system/other" } })
        );
    }
}
