//! Canonical JSON comparison: `live` vs the SSA `dryRun=All` prediction.
//!
//! # Why canonicalize
//!
//! Even a perfectly converged object never matches byte for byte: the API server stamps
//! `metadata.resourceVersion`, `uid`, `generation`, `creationTimestamp` and `managedFields`,
//! and every controller owns a slice of `.status`. Those are not drift, so both sides are
//! stripped before comparing:
//!
//! ```text
//! metadata.resourceVersion, metadata.uid, metadata.generation,
//! metadata.creationTimestamp, metadata.managedFields, top-level .status
//! ```
//!
//! Conversely, everything *outside* that volatile set is compared — including
//! `metadata.labels`, `metadata.annotations`, and API-defaulted fields. Defaulted fields are
//! fine because SSA `dryRun=All` predicts the post-default, post-webhook object, so a defaulted
//! `terminationMessagePath` produces zero diff while a hand-edited field produces a real one.
//!
//! # What is compared (finding C1)
//!
//! The **full object document** — `apiVersion`, `kind`, `metadata`, `spec`, everything — is
//! compared. `DynamicObject::data` is *not* the whole object: `metadata` and the type fields are
//! separate struct fields, so diffing `data` alone made every label/annotation edit invisible
//! (the drift was reported `Synced`). Callers hand over the serialized document
//! ([`crate::diff::ResourceDiff::compare`] takes plain `serde_json::Value`s), and the engine
//! derives each side's `group`/`kind` from that document for redaction.
//!
//! # Order of operations (do not reorder)
//!
//! 1. **clone** — the caller's desired payload must never be mutated (it is applied verbatim).
//! 2. **redact** `Secret` values and the `last-applied-configuration` annotation — before any
//!    value can reach a [`FieldChange`] or a log line (trap T4, finding H1).
//! 3. **strip volatile metadata / `.status`**.
//! 4. **remove `ignoreDifferences` pointers** — missing pointers are a no-op.
//! 5. **diff** into structured `Added`/`Removed`/`Modified` changes.
//!
//! # Bounds
//!
//! At most [`MAX_FIELD_CHANGES`] changes are recorded per resource (the tree walk still
//! produces a correct `OutOfSync`/`Synced` verdict, it just stops collecting); recursion depth
//! is bounded by `serde_json`'s 128-level parse limit, because every object here came from a
//! parsed document.

use serde_json::Value;

use crate::diff::ignore::IgnoreRuleSet;
use crate::diff::redact;
use crate::diff::types::{ChangeKind, DiffStatus, FieldChange, ResourceDiff};
use crate::manifest::ResourceKey;

/// Metadata fields every API server write changes, so they can never signal drift.
pub const VOLATILE_METADATA_FIELDS: [&str; 5] = [
    "resourceVersion",
    "uid",
    "generation",
    "creationTimestamp",
    "managedFields",
];

/// Hard cap on recorded field changes per resource.
///
/// A single mis-scoped `Application` can otherwise produce a diff proportional to the whole
/// object graph (a re-created `Deployment` diffing every container field). The verdict is
/// computed independently of the cap, so truncation never changes `Synced`/`OutOfSync`.
pub const MAX_FIELD_CHANGES: usize = 100;

/// Strips volatile metadata and the top-level `.status` from `object` in place.
pub fn strip_volatile(object: &mut Value) {
    let Some(map) = object.as_object_mut() else {
        return;
    };
    // `.status` belongs to controllers, never to Git.
    map.remove("status");
    if let Some(Value::Object(metadata)) = map.get_mut("metadata") {
        for field in VOLATILE_METADATA_FIELDS {
            metadata.remove(field);
        }
    }
}

/// Returns a canonicalized **clone** of `object` (see [`strip_volatile`]).
///
/// The input is never mutated: callers routinely pass the desired payload that is about to be
/// applied, and mutating it would silently corrupt the SSA body.
#[must_use]
pub fn canonicalize(object: &Value) -> Value {
    let mut canonical = object.clone();
    strip_volatile(&mut canonical);
    canonical
}

/// Escapes one RFC 6901 JSON Pointer reference token (`~` -> `~0`, `/` -> `~1`).
#[must_use]
pub fn escape_token(token: &str) -> String {
    let mut escaped = String::with_capacity(token.len());
    for character in token.chars() {
        match character {
            '~' => escaped.push_str("~0"),
            '/' => escaped.push_str("~1"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Appends one reference token to `path`, escaping it.
fn child_path(path: &str, token: &str) -> String {
    format!("{path}/{}", escape_token(token))
}

/// Collects field changes up to [`MAX_FIELD_CHANGES`].
#[derive(Debug, Default)]
struct ChangeSink {
    changes: Vec<FieldChange>,
    truncated: bool,
}

impl ChangeSink {
    /// Records one change, or flags truncation once the bound is reached.
    fn push(
        &mut self,
        path: &str,
        kind: ChangeKind,
        live: Option<&Value>,
        predicted: Option<&Value>,
    ) {
        if self.changes.len() >= MAX_FIELD_CHANGES {
            self.truncated = true;
            return;
        }
        self.changes.push(FieldChange::new(
            path.to_owned(),
            kind,
            live.cloned(),
            predicted.cloned(),
        ));
    }
}

/// Recursively diffs two canonicalized JSON values, recording every difference under `path`.
fn diff_values(path: &str, live: Option<&Value>, predicted: Option<&Value>, sink: &mut ChangeSink) {
    match (live, predicted) {
        (Some(Value::Object(live_map)), Some(Value::Object(predicted_map))) => {
            // Union of both key sets, sorted so the report is deterministic across runs and
            // across `serde_json` map implementations.
            let mut keys: Vec<&String> = live_map.keys().chain(predicted_map.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                diff_values(
                    &child_path(path, key),
                    live_map.get(key),
                    predicted_map.get(key),
                    sink,
                );
            }
        }
        (Some(Value::Array(live_items)), Some(Value::Array(predicted_items))) => {
            // Compare positionally: a shorter array shows up as `Removed` entries rather than
            // one opaque "the array changed".
            let length = live_items.len().max(predicted_items.len());
            for index in 0..length {
                diff_values(
                    &format!("{path}/{index}"),
                    live_items.get(index),
                    predicted_items.get(index),
                    sink,
                );
            }
        }
        (Some(live_value), Some(predicted_value)) => {
            if live_value != predicted_value {
                sink.push(
                    path,
                    ChangeKind::Modified,
                    Some(live_value),
                    Some(predicted_value),
                );
            }
        }
        (Some(live_value), None) => {
            sink.push(path, ChangeKind::Removed, Some(live_value), None);
        }
        (None, Some(predicted_value)) => {
            sink.push(path, ChangeKind::Added, None, Some(predicted_value));
        }
        (None, None) => {}
    }
}

impl ResourceDiff {
    /// Computes the diff of one resource from its live and predicted payloads.
    ///
    /// This is the **only** constructor that accepts raw objects, which makes it the single
    /// enforcement point for `Secret` redaction and for the "never mutate the desired payload"
    /// invariant: everything below operates on clones.
    ///
    /// `live` and `predicted` are the **full object documents** (`apiVersion`, `kind`,
    /// `metadata`, `spec`, …) — serialize the whole object, never just its `data` field, or
    /// `metadata` drift is silently reported `Synced` (finding C1).
    #[must_use]
    pub fn compare(
        key: &ResourceKey,
        live: &Value,
        predicted: &Value,
        rules: &IgnoreRuleSet,
    ) -> Self {
        let mut live_document = live.clone();
        let mut predicted_document = predicted.clone();

        // 1. Redaction first: no raw `Secret` value may reach a change, a `Debug` impl, or a log.
        //    The document's own `apiVersion`/`kind` decides, with the key as the fallback.
        redact::redact_document(&mut live_document, &key.group, &key.kind);
        redact::redact_document(&mut predicted_document, &key.group, &key.kind);

        // 2. Volatile metadata and `.status` are never drift.
        strip_volatile(&mut live_document);
        strip_volatile(&mut predicted_document);

        // 3. `spec.ignoreDifferences` on both clones (missing pointers are a no-op).
        rules.apply(
            &key.group,
            &key.kind,
            key.namespace.as_deref(),
            &key.name,
            &mut live_document,
        );
        rules.apply(
            &key.group,
            &key.kind,
            key.namespace.as_deref(),
            &key.name,
            &mut predicted_document,
        );

        // 4. Structured comparison.
        let mut sink = ChangeSink::default();
        diff_values(
            "",
            Some(&live_document),
            Some(&predicted_document),
            &mut sink,
        );

        let status = if sink.changes.is_empty() {
            DiffStatus::Synced
        } else {
            DiffStatus::OutOfSync
        };
        Self::assemble(
            key.clone(),
            status,
            sink.changes,
            Vec::new(),
            sink.truncated,
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::diff::types::DiffSummary;

    fn deployment_key() -> ResourceKey {
        ResourceKey::new("apps", "Deployment", Some("payments".to_owned()), "api")
    }

    fn live_deployment() -> Value {
        json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": "api",
                "namespace": "payments",
                "resourceVersion": "481516",
                "uid": "0d5a1c1e-0000-4000-8000-000000000000",
                "generation": 7,
                "creationTimestamp": "2026-11-24T12:00:00Z",
                "managedFields": [ { "manager": "ferriscd", "operation": "Apply" } ],
                "labels": { "app": "api" },
            },
            "spec": {
                "replicas": 2,
                "template": {
                    "spec": {
                        "containers": [ {
                            "name": "api",
                            "image": "ghcr.io/example/api:v1",
                            "terminationMessagePath": "/dev/termination-log",
                        } ],
                    },
                },
            },
            "status": { "replicas": 2, "conditions": [ { "type": "Available" } ] },
        })
    }

    /// The `dryRun=All` prediction of the same object: identical payload plus the volatile
    /// metadata and defaulted fields the API server adds.
    fn predicted_deployment() -> Value {
        let mut predicted = live_deployment();
        predicted["metadata"]["resourceVersion"] = json!("999999");
        predicted["metadata"]["uid"] = json!("11111111-1111-4111-8111-111111111111");
        predicted["metadata"]["generation"] = json!(8);
        predicted["metadata"]["creationTimestamp"] = json!("2026-11-25T00:00:00Z");
        predicted["metadata"]["managedFields"] = json!([ { "manager": "hpa" } ]);
        predicted["status"] = json!({ "replicas": 0 });
        predicted
    }

    #[test]
    fn volatile_metadata_defaults_and_status_produce_zero_diff() {
        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live_deployment(),
            &predicted_deployment(),
            &IgnoreRuleSet::default(),
        );
        assert_eq!(
            diff.status(),
            &DiffStatus::Synced,
            "volatile metadata, defaulted fields, and .status must never be drift: {:?}",
            diff.changes()
        );
        assert!(diff.changes().is_empty());
        assert!(!diff.is_truncated());
    }

    #[test]
    fn api_defaulted_fields_count_as_synced_only_because_the_prediction_has_them() {
        // The API server defaulted `terminationMessagePath` on the live object, and Git does not
        // mention it. Comparing live against the *rendered* object reports a phantom removal;
        // comparing against the `dryRun=All` prediction (which defaulted it too) does not.
        // This is exactly the false positive SSA dry-run diffing exists to remove.
        let live = live_deployment();
        let mut rendered = live_deployment();
        rendered["spec"]["template"]["spec"]["containers"][0]
            .as_object_mut()
            .expect("container object")
            .remove("terminationMessagePath");

        let versus_rendered = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &rendered,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(versus_rendered.status(), &DiffStatus::OutOfSync);
        assert_eq!(
            versus_rendered.changes()[0].path,
            "/spec/template/spec/containers/0/terminationMessagePath"
        );
        assert_eq!(versus_rendered.changes()[0].kind, ChangeKind::Removed);

        let versus_predicted = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted_deployment(),
            &IgnoreRuleSet::default(),
        );
        assert_eq!(versus_predicted.status(), &DiffStatus::Synced);
    }

    #[test]
    fn stripping_never_mutates_the_input_objects() {
        let live = live_deployment();
        let predicted = predicted_deployment();
        let live_before = live.clone();
        let predicted_before = predicted.clone();

        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::from_ignore_differences(&[]),
        );
        assert_eq!(live, live_before, "the live payload must not be mutated");
        assert_eq!(
            predicted, predicted_before,
            "the desired/predicted payload must not be mutated"
        );
        assert!(diff.is_synced());

        // `canonicalize` is a clone with the volatile fields removed.
        let canonical = canonicalize(&live);
        assert!(canonical.get("status").is_none());
        assert!(canonical["metadata"].get("managedFields").is_none());
        assert_eq!(canonical["spec"], live["spec"]);
        assert_eq!(live, live_before);
    }

    #[test]
    fn nested_objects_are_diffed_at_the_leaf() {
        let live = json!({ "spec": { "a": { "b": { "c": 1, "d": 2 } } } });
        let predicted = json!({ "spec": { "a": { "b": { "c": 1, "d": 3 } } } });

        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(diff.status(), &DiffStatus::OutOfSync);
        assert_eq!(diff.changes().len(), 1);
        let change = &diff.changes()[0];
        assert_eq!(change.path, "/spec/a/b/d");
        assert_eq!(change.kind, ChangeKind::Modified);
        assert_eq!(change.live, Some(json!(2)));
        assert_eq!(change.predicted, Some(json!(3)));
    }

    #[test]
    fn added_and_removed_fields_are_reported_per_path() {
        let live = json!({ "metadata": { "labels": { "keep": "1", "gone": "2" } }, "spec": {} });
        let predicted =
            json!({ "metadata": { "labels": { "keep": "1", "new": "3" } }, "spec": { "x": 1 } });

        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        let changes: Vec<(&str, ChangeKind)> = diff
            .changes()
            .iter()
            .map(|change| (change.path.as_str(), change.kind))
            .collect();
        assert_eq!(
            changes,
            vec![
                ("/metadata/labels/gone", ChangeKind::Removed),
                ("/metadata/labels/new", ChangeKind::Added),
                ("/spec/x", ChangeKind::Added),
            ],
            "changes must be sorted by path and classified"
        );
        assert_eq!(diff.changes()[0].predicted, None);
        assert_eq!(diff.changes()[1].live, None);
    }

    #[test]
    fn array_length_differences_are_reported_per_index() {
        let live = json!({ "spec": { "items": [ "a", "b", "c" ] } });
        let predicted = json!({ "spec": { "items": [ "a", "b" ] } });

        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(diff.changes().len(), 1);
        assert_eq!(diff.changes()[0].path, "/spec/items/2");
        assert_eq!(diff.changes()[0].kind, ChangeKind::Removed);

        // A type change on a container (object -> scalar) is one `Modified`, not a crash.
        let live = json!({ "spec": { "value": { "a": 1 } } });
        let predicted = json!({ "spec": { "value": "scalar" } });
        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(diff.changes().len(), 1);
        assert_eq!(diff.changes()[0].path, "/spec/value");
        assert_eq!(diff.changes()[0].kind, ChangeKind::Modified);
    }

    #[test]
    fn pointer_tokens_in_paths_are_escaped() {
        let key = ResourceKey::new("", "ConfigMap", Some("payments".to_owned()), "settings");
        let live = json!({ "data": { "app/config": "a", "a~b": "c" } });
        let predicted = json!({ "data": { "app/config": "a2", "a~b": "c2" } });

        let diff = ResourceDiff::compare(&key, &live, &predicted, &IgnoreRuleSet::default());
        let paths: Vec<&str> = diff
            .changes()
            .iter()
            .map(|change| change.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec!["/data/app~1config", "/data/a~0b"],
            "paths are sorted by their raw tokens (`app/config` < `a~b`), then escaped"
        );
        assert_eq!(escape_token("a/b~c"), "a~1b~0c");
        assert_eq!(escape_token("plain"), "plain");
    }

    /// Finding M3: an ignore rule that *does* remove a pointer must leave the caller's inputs
    /// untouched — the desired payload is applied verbatim right after the diff.
    #[test]
    fn a_removing_ignore_rule_never_mutates_the_callers_inputs() {
        let rules = IgnoreRuleSet::from_ignore_differences(&[ferriscd_crd::IgnoreDifference {
            group: Some("apps".to_owned()),
            kind: "Deployment".to_owned(),
            json_pointers: vec![
                "/spec/replicas".to_owned(),
                "/metadata/annotations/example.com~1owner".to_owned(),
            ],
            ..ferriscd_crd::IgnoreDifference::default()
        }]);

        let mut live = live_deployment();
        live["spec"]["replicas"] = json!(1);
        live["metadata"]["annotations"] = json!({ "example.com/owner": "platform" });
        let mut predicted = predicted_deployment();
        predicted["spec"]["replicas"] = json!(9);
        predicted["metadata"]["annotations"] = json!({ "example.com/owner": "payments" });

        let live_before = live.clone();
        let predicted_before = predicted.clone();

        let diff = ResourceDiff::compare(&deployment_key(), &live, &predicted, &rules);
        assert_eq!(diff.status(), &DiffStatus::Synced);
        assert_eq!(diff.changes().len(), 0, "{:?}", diff.changes());
        assert_eq!(live, live_before, "the live payload must not be mutated");
        assert_eq!(
            predicted, predicted_before,
            "the desired/predicted payload must not be mutated"
        );
        // Both ignored pointers really existed on both sides (so the rule did the work).
        assert_eq!(live_before["spec"]["replicas"], json!(1));
        assert_eq!(predicted_before["spec"]["replicas"], json!(9));
    }

    #[test]
    fn ignore_differences_are_applied_to_both_sides() {
        let rules = IgnoreRuleSet::from_ignore_differences(&[ferriscd_crd::IgnoreDifference {
            group: Some("apps".to_owned()),
            kind: "Deployment".to_owned(),
            json_pointers: vec!["/spec/replicas".to_owned()],
            ..ferriscd_crd::IgnoreDifference::default()
        }]);

        let mut live = live_deployment();
        live["spec"]["replicas"] = json!(1);
        let mut predicted = predicted_deployment();
        predicted["spec"]["replicas"] = json!(9);

        let ignored = ResourceDiff::compare(&deployment_key(), &live, &predicted, &rules);
        assert_eq!(
            ignored.status(),
            &DiffStatus::Synced,
            "the HPA-style /spec/replicas difference must be ignored"
        );

        // Without the rule the same pair is out of sync, proving the rule did the work.
        let not_ignored = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(not_ignored.status(), &DiffStatus::OutOfSync);
        assert_eq!(not_ignored.changes()[0].path, "/spec/replicas");
    }

    #[test]
    fn missing_ignored_pointers_do_not_error() {
        let rules = IgnoreRuleSet::from_ignore_differences(&[ferriscd_crd::IgnoreDifference {
            kind: "Deployment".to_owned(),
            json_pointers: vec!["/spec/does/not/exist".to_owned()],
            ..ferriscd_crd::IgnoreDifference::default()
        }]);
        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live_deployment(),
            &predicted_deployment(),
            &rules,
        );
        assert_eq!(diff.status(), &DiffStatus::Synced);
    }

    #[test]
    fn results_are_deterministic_across_runs_and_key_order() {
        let live = json!({
            "metadata": { "b": 1, "a": 2 },
            "spec": { "z": [ 1, 2 ], "y": { "n": 1 } },
        });
        let predicted = json!({
            "metadata": { "a": 2, "b": 9 },
            "spec": { "y": { "n": 2 }, "z": [ 1 ] },
        });

        let first = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        let second = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(first.changes(), second.changes());

        let paths: Vec<&str> = first
            .changes()
            .iter()
            .map(|change| change.path.as_str())
            .collect();
        assert_eq!(paths, {
            let mut sorted = paths.clone();
            sorted.sort_unstable();
            sorted
        });

        // Key insertion order must not matter: rebuild both maps with reversed insertion.
        let live_reordered = json!({
            "spec": { "y": { "n": 1 }, "z": [ 1, 2 ] },
            "metadata": { "a": 2, "b": 1 },
        });
        let third = ResourceDiff::compare(
            &deployment_key(),
            &live_reordered,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(third.changes(), first.changes());
    }

    #[test]
    fn change_collection_is_bounded_but_the_verdict_is_not() {
        let mut live = serde_json::Map::new();
        let mut predicted = serde_json::Map::new();
        for index in 0..(MAX_FIELD_CHANGES * 3) {
            live.insert(format!("field{index:03}"), json!(index));
            predicted.insert(format!("field{index:03}"), json!(index + 1));
        }
        let live = Value::Object(live);
        let predicted = Value::Object(predicted);

        let diff = ResourceDiff::compare(
            &deployment_key(),
            &live,
            &predicted,
            &IgnoreRuleSet::default(),
        );
        assert_eq!(diff.changes().len(), MAX_FIELD_CHANGES);
        assert!(diff.is_truncated());
        assert_eq!(
            diff.status(),
            &DiffStatus::OutOfSync,
            "truncation must never hide the verdict"
        );
        assert_eq!(diff.changes()[0].path, "/field000");
    }

    #[test]
    fn an_orphan_and_a_missing_resource_carry_no_changes() {
        let orphan = ResourceDiff::orphaned(deployment_key());
        assert_eq!(orphan.status(), &DiffStatus::Orphaned);
        assert!(orphan.changes().is_empty());
        let summary = DiffSummary::from_diffs([&orphan]);
        assert_eq!(summary.orphaned, 1);
        assert!(summary.has_orphans());

        let missing = ResourceDiff::missing(deployment_key());
        assert_eq!(missing.status(), &DiffStatus::Missing);
        assert!(DiffSummary::from_diffs([&missing]).has_drift());
    }
}
