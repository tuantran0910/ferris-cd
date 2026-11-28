//! Canonical control annotations **and ownership labels** for FerrisCD custom resources.
//!
//! Every operator/user control surface annotation is declared here exactly once so
//! controllers, the CLI, and tests never hand-roll string literals. Scattering these
//! keys is how control annotations get silently dropped from watch predicates and
//! finalizer logic (Finding C5).
//!
//! The [`MANAGED_RESOURCE_LABELS`] pair lives here for the same reason: a watch label selector
//! hard-coded in one place and stamped in another is exactly how a selector silently stops
//! matching every object (`T18.1`, Finding M5).

/// Common prefix of every FerrisCD annotation and label key.
pub const PREFIX: &str = "ferriscd.io/";

/// `ferriscd.io/refresh` — opaque token; mutating it requests an immediate reconcile.
pub const REFRESH: &str = "ferriscd.io/refresh";

/// `ferriscd.io/operation` — JSON-encoded operation request (`{"sync":{"revision":"..."}}`).
pub const OPERATION: &str = "ferriscd.io/operation";

/// `ferriscd.io/cascade-delete` — `"true"` deletes every resource in `status.inventory`
/// (verified by [`TRACKING_ID`]) when the `Application` is deleted.
pub const CASCADE_DELETE: &str = "ferriscd.io/cascade-delete";

/// `ferriscd.io/force-delete` — `"true"` releases the finalizer even if cleanup fails
/// (escape hatch for an unreachable destination cluster).
pub const FORCE_DELETE: &str = "ferriscd.io/force-delete";

/// `ferriscd.io/tracking-id` — ownership marker stamped onto every managed resource.
///
/// Format: `<app-ns>/<app-name>:<group>/<kind>:<res-ns>/<res-name>` (version-agnostic).
pub const TRACKING_ID: &str = "ferriscd.io/tracking-id";

/// `ferriscd.io/sync-wave` — decimal `i32` ordering hint (default `0`); lower runs first.
pub const SYNC_WAVE: &str = "ferriscd.io/sync-wave";

/// `ferriscd.io/hook` — lifecycle hook phase (`PreSync`, `Sync`, `PostSync`, `SyncFail`).
pub const HOOK: &str = "ferriscd.io/hook";

/// `ferriscd.io/hook-delete-policy` — when a hook resource is deleted after it runs
/// (`hook-succeeded`, `hook-failed`, `before-hook-creation`).
pub const HOOK_DELETE_POLICY: &str = "ferriscd.io/hook-delete-policy";

/// `ferriscd.io/sync-options` — comma-separated per-resource sync option overrides.
pub const SYNC_OPTIONS: &str = "ferriscd.io/sync-options";

/// `ferriscd.io/prune` — `"false"` opts a single live resource out of pruning.
pub const PRUNE: &str = "ferriscd.io/prune";

/// Prefix of every notification subscription annotation (`T19.4`).
///
/// Deliberately **outside** [`CONTROL_ANNOTATIONS`]: subscribing an `Application` to a notification
/// service changes nothing about how it is reconciled, so the composite watch predicate must ignore
/// it (an edit emits no reconcile). It is `notifications.ferriscd.io/`, not
/// [`PREFIX`]`notifications/`, so a tenant cannot mistake it for a control annotation.
pub const NOTIFICATIONS_PREFIX: &str = "notifications.ferriscd.io/";

/// Prefix of the opt-in notification subscription annotations (`T19.4`).
///
/// Full key: `notifications.ferriscd.io/subscribe.<trigger>.<service>`, value: the recipient (the
/// name of a `ferriscd.io/secret-type=notifications` `Secret` in the control-plane namespace).
pub const NOTIFICATIONS_SUBSCRIBE_PREFIX: &str = "notifications.ferriscd.io/subscribe.";

/// Trigger: a sync pass succeeded (edge-triggered on entering `Synced`).
pub const TRIGGER_SYNC_SUCCEEDED: &str = "on-sync-succeeded";

/// Trigger: a sync/reconcile failed (`Ready=False`, edge-triggered).
pub const TRIGGER_SYNC_FAILED: &str = "on-sync-failed";

/// Trigger: the aggregated health degraded (edge-triggered on entering `Degraded`).
pub const TRIGGER_HEALTH_DEGRADED: &str = "on-health-degraded";

/// Trigger: the `Application` is out of sync (debounced, see `T19.4`).
pub const TRIGGER_OUT_OF_SYNC: &str = "on-out-of-sync";

/// Every notification trigger, in documentation order.
pub const TRIGGER_NAMES: [&str; 4] = [
    TRIGGER_SYNC_SUCCEEDED,
    TRIGGER_SYNC_FAILED,
    TRIGGER_HEALTH_DEGRADED,
    TRIGGER_OUT_OF_SYNC,
];

/// `ferriscd.io/managed-by` — label marking an object as managed by FerrisCD (`T18.1`).
///
/// Stamped onto the top-level `metadata.labels` of every non-hook managed resource so the
/// opt-in `DriftWatcher` can filter **server-side** with
/// `ferriscd.io/managed-by=ferriscd` (`T18.2`): a watch label selector is the only filter the API
/// server can apply before any object byte crosses the wire, and annotations cannot be selected
/// on. The value is always [`MANAGED_BY_FERRISCD`].
///
/// Never stamped into an immutable `spec.selector.matchLabels` (that breaks existing
/// `Deployment`/`StatefulSet` applies with `422 Immutable`) — see [`crate::annotations::TRACKING_ID`]
/// and `stamp_tracking_id`.
pub const LABEL_MANAGED_BY: &str = "ferriscd.io/managed-by";

/// The value [`LABEL_MANAGED_BY`] always carries.
pub const MANAGED_BY_FERRISCD: &str = "ferriscd";

/// `ferriscd.io/app-hash` — bounded, collision-resistant identity of the owning `Application`
/// (`T18.1`).
///
/// The value is the first 16 lowercase hex characters (64 bits) of
/// `SHA-256("<app-namespace>/<app-name>")`, so it is **always** 16 `[0-9a-f]` characters —
/// valid under the 63-character Kubernetes label-value limit no matter how long the
/// `Application` name (up to 253 characters) or its namespace is. Hashing the `namespace/name`
/// pair in one string is what keeps `ns-a/app` and `ns-b/app` distinct (Finding M5: a bare
/// `ferriscd.io/app: <name>` collides across namespaces and overflows the label limit).
///
/// A `DriftWatcher` hit only *triggers* a reconcile: exact ownership is still verified against
/// [`TRACKING_ID`], so a theoretical 64-bit collision costs at most one no-op reconcile.
pub const LABEL_APP_HASH: &str = "ferriscd.io/app-hash";

/// Every label FerrisCD stamps onto a managed resource (`T18.1`).
///
/// A fixed, bounded key set: no label key is ever derived from an `Application` name, a
/// namespace, a cluster name, or a repository URL, so the label surface cannot grow with the
/// fleet.
pub const MANAGED_RESOURCE_LABELS: [&str; 2] = [LABEL_MANAGED_BY, LABEL_APP_HASH];
/// Every canonical control annotation key.
///
/// Watch predicates (Phase 05) hash exactly this set plus finalizers and deletion
/// timestamps so control-annotation changes are never swallowed.
pub const CONTROL_ANNOTATIONS: [&str; 10] = [
    REFRESH,
    OPERATION,
    CASCADE_DELETE,
    FORCE_DELETE,
    TRACKING_ID,
    SYNC_WAVE,
    HOOK,
    HOOK_DELETE_POLICY,
    SYNC_OPTIONS,
    PRUNE,
];

/// Interprets a boolean control-annotation value.
///
/// Only `"true"` (case-insensitive) and `"1"` enable a flag; everything else —
/// including a missing annotation — is treated as disabled, so a typo can never
/// accidentally enable cascade deletion or forced finalizer release.
#[must_use]
pub fn is_enabled(value: Option<&str>) -> bool {
    match value {
        Some(raw) => {
            let trimmed = raw.trim();
            trimmed.eq_ignore_ascii_case("true") || trimmed == "1"
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_control_annotation_is_namespaced_and_unique() {
        let mut seen = HashSet::new();
        for key in CONTROL_ANNOTATIONS {
            assert!(
                key.starts_with(PREFIX),
                "annotation {key} must live under {PREFIX}"
            );
            assert!(
                key.len() > PREFIX.len(),
                "annotation {key} must have a non-empty suffix"
            );
            assert!(
                !key[PREFIX.len()..].contains('/'),
                "annotation {key} must have a single-segment suffix"
            );
            assert!(seen.insert(key), "duplicate annotation key {key}");
        }
        assert_eq!(seen.len(), CONTROL_ANNOTATIONS.len());
    }

    #[test]
    fn control_annotation_values_match_documented_contract() {
        assert_eq!(REFRESH, "ferriscd.io/refresh");
        assert_eq!(OPERATION, "ferriscd.io/operation");
        assert_eq!(CASCADE_DELETE, "ferriscd.io/cascade-delete");
        assert_eq!(FORCE_DELETE, "ferriscd.io/force-delete");
        assert_eq!(TRACKING_ID, "ferriscd.io/tracking-id");
        assert_eq!(SYNC_WAVE, "ferriscd.io/sync-wave");
        assert_eq!(HOOK, "ferriscd.io/hook");
        assert_eq!(HOOK_DELETE_POLICY, "ferriscd.io/hook-delete-policy");
        assert_eq!(SYNC_OPTIONS, "ferriscd.io/sync-options");
        assert_eq!(PRUNE, "ferriscd.io/prune");
    }

    /// **`T19.4`:** the notification subscription keys live outside [`CONTROL_ANNOTATIONS`] (an edit
    /// must never trigger a reconcile) and their trigger names match the roadmap spelling exactly.
    #[test]
    fn notification_annotations_are_outside_the_control_set() {
        assert_eq!(
            NOTIFICATIONS_SUBSCRIBE_PREFIX,
            "notifications.ferriscd.io/subscribe."
        );
        assert!(NOTIFICATIONS_SUBSCRIBE_PREFIX.starts_with(NOTIFICATIONS_PREFIX));
        for key in CONTROL_ANNOTATIONS {
            assert!(
                !key.starts_with("notifications."),
                "{key} must not be a control annotation"
            );
        }
        assert_eq!(
            TRIGGER_NAMES,
            [
                "on-sync-succeeded",
                "on-sync-failed",
                "on-health-degraded",
                "on-out-of-sync",
            ]
        );
        let mut seen = HashSet::new();
        for trigger in TRIGGER_NAMES {
            assert!(seen.insert(trigger), "duplicate trigger {trigger}");
        }
    }

    #[test]
    fn is_enabled_requires_explicit_truthy_value() {
        for truthy in ["true", "TRUE", "True", " true ", "1"] {
            assert!(
                is_enabled(Some(truthy)),
                "expected {truthy:?} to be enabled"
            );
        }
        for falsy in ["false", "FALSE", "0", "", "yes", "no", "2", "truee"] {
            assert!(
                !is_enabled(Some(falsy)),
                "expected {falsy:?} to be disabled"
            );
        }
        assert!(!is_enabled(None));
    }

    /// `T18.1`: the stamped label pair is a fixed, namespaced, unique key set — a watch selector
    /// hard-coded elsewhere can only keep matching if these keys never drift.
    #[test]
    fn managed_resource_labels_are_namespaced_unique_and_exact() {
        assert_eq!(LABEL_MANAGED_BY, "ferriscd.io/managed-by");
        assert_eq!(LABEL_APP_HASH, "ferriscd.io/app-hash");
        assert_eq!(MANAGED_BY_FERRISCD, "ferriscd");
        assert_eq!(
            MANAGED_RESOURCE_LABELS,
            ["ferriscd.io/managed-by", "ferriscd.io/app-hash"]
        );

        let mut seen = HashSet::new();
        for key in MANAGED_RESOURCE_LABELS {
            assert!(
                key.starts_with(PREFIX),
                "label {key} must live under {PREFIX}"
            );
            assert!(
                !key[PREFIX.len()..].contains('/'),
                "label {key} must have a single-segment suffix"
            );
            assert!(seen.insert(key), "duplicate label key {key}");
            // A label key that also names a control annotation would be stamped twice by
            // different code paths and could never be reasoned about.
            assert!(
                !CONTROL_ANNOTATIONS.contains(&key),
                "label {key} must not collide with a control annotation"
            );
        }
        assert_eq!(seen.len(), MANAGED_RESOURCE_LABELS.len());
    }
}
