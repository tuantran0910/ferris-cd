//! Canonical control annotations for FerrisCD custom resources.
//!
//! Every operator/user control surface annotation is declared here exactly once so
//! controllers, the CLI, and tests never hand-roll string literals. Scattering these
//! keys is how control annotations get silently dropped from watch predicates and
//! finalizer logic (Finding C5).

/// Common prefix of every FerrisCD annotation key.
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
}
